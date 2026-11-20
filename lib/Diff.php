<?php
declare(strict_types=1);

namespace Fls;

/** Deterministic diff (no model): new / spike / new fatal, baseline warming, known-harmless. */
final class Diff
{
    public static function key(string $level, string $category, string $template): string
    {
        return hash('sha256', $level . "\x1f" . $category . "\x1f" . $template);
    }

    /**
     * Fatal means a fatal level, a PHP fatal, a ParseError, memory exhaustion, an uncaught exception or an HTTP 5xx.
     * ErrorException with E_ERROR/E_PARSE/E_COMPILE_ERROR/E_RECOVERABLE_ERROR (1, 4, 64, 256) matches only while the
     * category still carries its digits; templates normalized to ErrorException:{n} cannot be told apart, so they stay
     * non-fatal. A plain error, undefined index/key and "Fork child failed" are not fatal.
     */
    public static function isFatal(string $level, string $category, string $template): bool
    {
        return $level === 'fatal'
            || (bool)preg_match('/(?<![\w-])fatal(?:error|throwable|\b)|\buncaught\b|HttpException:5\d\d|\bhttp_status\W*5\d\d|\bParseError\b|Allowed memory size|ErrorException:(?:1|4|64|256)\b(?!\d)/i', $category . ' ' . $template);
    }

    /** A role is on its version baseline until a run with the current normalizer version recorded it. */
    public static function roleOnBaseline(array $history, string $role): bool
    {
        foreach ($history['runs'] ?? [] as $r) {
            if (($r['normalizer_version'] ?? null) === Family::VERSION && isset($r['roles'][$role])) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param array $observed list of {role, class, key, level, category, template, count, hours[, raw_template]}
     * @param ?list<string> $roles roles read this run (so a quiet role still counts); default: roles in $observed
     * @return array{flags: array, baseline: bool, historyDays: int}
     */
    public static function evaluate(string $site, array $history, array $observed, int $now, array $cfg, KnownHarmless $kh, ?array $roles = null): array
    {
        $d = $cfg['diff'];
        $hdays = GroupHistory::historyDays($history, $now, (int)$d['history_days']);
        $flags = [];
        if ($hdays === 0 && !$history['runs']) {
            return ['flags' => [], 'baseline' => true, 'historyDays' => 0];
        }
        $seenRoles = array_map('strval', $roles ?? []);
        foreach ($observed as $o) {
            $seenRoles[] = (string)$o['role'];
        }
        $onBase = [];
        foreach (array_unique($seenRoles) as $role) {
            $onBase[$role] = self::roleOnBaseline($history, $role);
        }
        $baseline = $onBase && !in_array(false, $onBase, true);
        foreach ($observed as $o) {
            if ($onBase[(string)$o['role']] ?? false) {
                continue; // no current-version history for this role: it only records this run
            }
            $id = $o['role'] . '|' . $o['key'];
            $g = $history['groups'][$id] ?? null;
            $seen = $g !== null && (int)($g['last_seen'] ?? 0) >= $now - (int)$d['history_days'] * 86400;
            $harmless = $kh->match($site, $o['class'], $o['level'], $o['category'], (string)($o['raw_template'] ?? $o['template']));
            $rate = $o['count'] / max(1.0, (float)$o['hours']);
            if (!$seen) {
                if ($harmless !== null) {
                    continue;
                }
                $fatal = self::isFatal($o['level'], $o['category'], $o['template']);
                $flags[] = $o + ['site' => $site, 'flag' => $fatal ? 'new-fatal' : 'new', 'rate' => $rate, 'usual' => null, 'factor' => null];
                continue;
            }
            if ($hdays < (int)$d['warm_days']) {
                continue; // warming: only new/fatal fire
            }
            $med = GroupHistory::median(GroupHistory::dailyRates($g, $now, (int)$d['median_days']));
            if ($med <= 0) {
                continue;
            }
            $factor = $rate / $med;
            if ($factor >= (float)$d['spike_factor'] && $o['count'] >= (int)$d['spike_min_count']) {
                $flags[] = $o + ['site' => $site, 'flag' => 'spike', 'rate' => $rate, 'usual' => $med * max(1.0, (float)$o['hours']), 'factor' => $factor, 'harmless' => $harmless];
            }
        }
        return ['flags' => $flags, 'baseline' => $baseline, 'historyDays' => $hdays];
    }
}

/** Section-6 shaped digest. */
final class Digest
{
    public const FOOTER = [
        'Limits: wwkker cannot read /var/log/apache2 and there are no nginx/php-fpm logs, so "5xx" means only what Yii logged.',
        'Servers have no version file or .git, so the deployed version cannot be read. Times are Asia/Manila.',
    ];

    public static function render(array $run): string
    {
        $flags = $run['flags'];
        $fail = $run['failures'];
        $unreach = count(array_filter($fail, fn($f) => in_array($f['status'], ['unreachable', 'timeout', 'reset', 'skipped-breaker'], true)));
        $head = sprintf(
            'Fleet scan %s — %d servers, %d flagged, %d unreachable%s',
            Tz::manila($run['started'], 'd M H:i'),
            $run['servers'],
            count($flags),
            $unreach,
            $run['baseline_sites'] ? ' (baseline: ' . implode(', ', $run['baseline_sites']) . ')' : ''
        );
        $lines = [$head];
        if ($run['baseline_sites']) {
            $lines[] = sprintf('Baseline run for %d site(s): %d groups recorded, no alerts on a first run.', count($run['baseline_sites']), $run['baseline_groups']);
        }
        usort($flags, fn($a, $b) => [self::rank($a['flag']), $a['site'], $a['role']] <=> [self::rank($b['flag']), $b['site'], $b['role']]);
        foreach ($flags as $f) {
            $tpl = self::short($f['template']);
            $what = trim($f['category'] . ' "' . $tpl . '"');
            if ($f['flag'] === 'spike') {
                $lines[] = sprintf('%s %-8s %.1fx  %s %s  %d (usual %d)', $f['site'], $f['role'], $f['factor'], $f['level'], $what, $f['count'], (int)round($f['usual']));
            } else {
                $lines[] = sprintf('%s %-8s NEW %s  %s  %d%s', $f['site'], $f['role'], $f['flag'] === 'new-fatal' ? $f['level'] . ' (fatal/error/5xx)' : $f['level'], $what, $f['count'], $f['rate'] >= 1 ? sprintf(' (%d/h)', (int)round($f['rate'])) : '');
            }
        }
        foreach ($fail as $f) {
            $lines[] = sprintf('%s %-8s FAILED %s', $f['site'], $f['role'], $f['status']);
        }
        foreach ($run['observations'] as $o) {
            $lines[] = $o;
        }
        foreach ($run['notes'] as $n) {
            $lines[] = 'Note: ' . $n;
        }
        if (!empty($run['summary'])) {
            $lines[] = 'Summary (grok-4.7-xhigh-fast): ' . $run['summary'];
        } elseif (!empty($run['summary_status']) && $run['summary_status'] !== 'disabled') {
            $lines[] = $run['summary_status'];
        }
        foreach (self::FOOTER as $l) {
            $lines[] = '— ' . $l;
        }
        return implode("\n", $lines) . "\n";
    }

    private static function rank(string $f): int
    {
        return ['new-fatal' => 0, 'new' => 1, 'spike' => 2][$f] ?? 3;
    }

    public static function short(string $s, int $n = 90): string
    {
        return strlen($s) > $n ? substr($s, 0, $n - 1) . '…' : $s;
    }
}
