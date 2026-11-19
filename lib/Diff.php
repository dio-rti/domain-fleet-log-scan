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

    public static function isFatal(string $level, string $category, string $template): bool
    {
        return $level === 'error'
            || (bool)preg_match('/fatal|uncaught|HttpException:5\d\d|\bhttp_status\W*5\d\d|(?<!\.php:)\b5\d\d\b/i', $category . ' ' . $template);
    }

    /**
     * @param array $observed list of {role, class, key, level, category, template, count, hours}
     * @return array{flags: array, baseline: bool, historyDays: int}
     */
    public static function evaluate(string $site, array $history, array $observed, int $now, array $cfg, KnownHarmless $kh): array
    {
        $d = $cfg['diff'];
        $hdays = GroupHistory::historyDays($history, $now, (int)$d['history_days']);
        $baseline = $hdays === 0 && !$history['runs'];
        $flags = [];
        if ($baseline) {
            return ['flags' => [], 'baseline' => true, 'historyDays' => 0];
        }
        foreach ($observed as $o) {
            $id = $o['role'] . '|' . $o['key'];
            $g = $history['groups'][$id] ?? null;
            $seen = $g !== null && (int)($g['last_seen'] ?? 0) >= $now - (int)$d['history_days'] * 86400;
            $harmless = $kh->match($site, $o['class'], $o['level'], $o['category'], $o['template']);
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
        return ['flags' => $flags, 'baseline' => false, 'historyDays' => $hdays];
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
