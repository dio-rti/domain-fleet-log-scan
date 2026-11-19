<?php
declare(strict_types=1);

namespace Fls;

/** Per-site checkpoints: role => label => {inode, offset, last_ts (epoch), size, mtime}. */
final class Checkpoints
{
    public static function path(string $stateDir, string $site): string
    {
        return $stateDir . '/checkpoints/' . $site . '.json';
    }

    public static function load(string $stateDir, string $site): array
    {
        return Fs::readJson(self::path($stateDir, $site));
    }

    /** Payload args for one role. */
    public static function args(array $cp, string $role): array
    {
        $out = [];
        foreach ($cp[$role] ?? [] as $label => $c) {
            if (!preg_match('/^[A-Za-z0-9._\/-]+$/', (string)$label) || !preg_match('/^\d+$/', (string)$c['inode']) || !preg_match('/^\d+$/', (string)$c['offset'])) {
                continue;
            }
            $ck = $label . ':' . $c['inode'] . ':' . $c['offset'] . ':' . (int)($c['last_ts'] ?? 0);
            $pl = (int)($c['prefix_len'] ?? 0);
            $ps = (string)($c['prefix_sum'] ?? '');
            if ($pl > 0 && preg_match('/^\d+$/', $ps)) {
                $ck .= ':' . $pl . ':' . $ps;
            }
            $out[] = ['ck', $ck];
        }
        return $out;
    }

    public static function advance(array $cp, string $role, Tsv $t, int $now): array
    {
        $off = $t->header['offset'] ?? '+0900';
        foreach ($t->files as $label => $f) {
            if (!$f['readable'] || !preg_match('/^\d+$/', (string)$f['inode'])) {
                continue;
            }
            $prev = $cp[$role][$label] ?? [];
            $last = $f['last_ts'] !== '-' ? Tz::serverTsToEpoch($f['last_ts'], $off) : null;
            $cp[$role][$label] = [
                'inode' => (string)$f['inode'],
                'offset' => (string)$f['offset'],
                'size' => (string)$f['size'],
                'mtime' => (string)$f['mtime'],
                'last_ts' => $last ?? ($prev['last_ts'] ?? 0),
                'prefix_len' => (int)($f['prefix_len'] ?? 0),
                'prefix_sum' => (string)($f['prefix_sum'] ?? '-'),
                'flags' => $f['flags'],
                'updated' => $now,
            ];
        }
        return $cp;
    }

    public static function save(string $stateDir, string $site, array $cp): void
    {
        Fs::writeJson(self::path($stateDir, $site), $cp);
    }
}

/** Per-site group history: rolling day buckets (Manila dates) of counts and hours. */
final class GroupHistory
{
    public static function path(string $stateDir, string $site): string
    {
        return $stateDir . '/groups/' . $site . '.json';
    }

    public static function load(string $stateDir, string $site): array
    {
        $h = Fs::readJson(self::path($stateDir, $site), ['runs' => [], 'groups' => []]);
        $h['runs'] ??= [];
        $h['groups'] ??= [];
        return $h;
    }

    /** Distinct prior run dates (before today) within $days. */
    public static function historyDays(array $h, int $now, int $days): int
    {
        $today = Tz::manilaDate($now);
        $d = [];
        foreach ($h['runs'] as $r) {
            if ($r['date'] !== $today && $r['epoch'] >= $now - $days * 86400) {
                $d[$r['date']] = true;
            }
        }
        return count($d);
    }

    public static function lastRunEpoch(array $h, string $role): ?int
    {
        $best = null;
        foreach ($h['runs'] as $r) {
            if (isset($r['roles'][$role])) {
                $best = max($best ?? 0, (int)$r['epoch']);
            }
        }
        return $best;
    }

    public static function median(array $xs): float
    {
        if (!$xs) {
            return 0.0;
        }
        sort($xs);
        $n = count($xs);
        return $n % 2 ? (float)$xs[intdiv($n, 2)] : ($xs[$n / 2 - 1] + $xs[$n / 2]) / 2;
    }

    /** Daily per-hour rates of a group over the last $days days, excluding today; only days it appeared. */
    public static function dailyRates(array $g, int $now, int $days): array
    {
        $today = Tz::manilaDate($now);
        $rates = [];
        foreach ($g['days'] ?? [] as $date => $b) {
            if ($date === $today || strtotime($date . ' 12:00:00 UTC') < $now - ($days + 1) * 86400) {
                continue;
            }
            if ($b['hours'] > 0 && $b['count'] > 0) {
                $rates[] = $b['count'] / $b['hours'];
            }
        }
        return $rates;
    }

    public static function record(array $h, int $now, array $roleHours, array $observed, int $keepDays): array
    {
        $date = Tz::manilaDate($now);
        $h['runs'][] = ['epoch' => $now, 'date' => $date, 'roles' => $roleHours];
        foreach ($observed as $o) {
            $id = $o['role'] . '|' . $o['key'];
            $g = $h['groups'][$id] ?? [
                'role' => $o['role'], 'key' => $o['key'], 'level' => $o['level'], 'category' => $o['category'],
                'template' => $o['template'], 'first_seen' => $o['first_epoch'] ?? $now, 'days' => [],
            ];
            $g['last_seen'] = max((int)($g['last_seen'] ?? 0), (int)($o['last_epoch'] ?? $now));
            $b = $g['days'][$date] ?? ['count' => 0, 'hours' => 0.0];
            $b['count'] += $o['count'];
            $b['hours'] += $roleHours[$o['role']] ?? 24.0;
            $g['days'][$date] = $b;
            $h['groups'][$id] = $g;
        }
        // prune
        $cut = $now - $keepDays * 86400;
        $h['runs'] = array_values(array_filter($h['runs'], fn($r) => $r['epoch'] >= $cut));
        foreach ($h['groups'] as $id => $g) {
            if (($g['last_seen'] ?? 0) < $cut) {
                unset($h['groups'][$id]);
                continue;
            }
            foreach ($g['days'] as $d => $_) {
                if (strtotime($d . ' 12:00:00 UTC') < $cut - 86400) {
                    unset($h['groups'][$id]['days'][$d]);
                }
            }
        }
        return $h;
    }

    public static function save(string $stateDir, string $site, array $h): void
    {
        Fs::writeJson(self::path($stateDir, $site), $h);
    }
}

/** Seeded known-harmless cache (plan section 6). */
final class KnownHarmless
{
    public function __construct(private array $seeds) {}

    public static function load(array $cfg): self
    {
        $p = $cfg['data_dir'] . '/state/known-harmless.json';
        if (!is_file($p)) {
            $p = $cfg['tool_dir'] . '/state/known-harmless.json';
        }
        $j = Fs::readJson($p, ['seeds' => []]);
        return new self($j['seeds'] ?? []);
    }

    public function match(string $site, string $roleClass, string $level, string $category, string $template): ?string
    {
        foreach ($this->seeds as $s) {
            $sites = $s['sites'] ?? '*';
            if ($sites !== '*' && !in_array($site, (array)$sites, true)) {
                continue;
            }
            $roles = $s['roles'] ?? '*';
            if ($roles !== '*' && !in_array($roleClass, (array)$roles, true)) {
                continue;
            }
            if (isset($s['level']) && $s['level'] !== $level) {
                continue;
            }
            if (isset($s['category_re']) && !preg_match('~' . $s['category_re'] . '~i', $category)) {
                continue;
            }
            if (isset($s['template_re']) && !preg_match('~' . $s['template_re'] . '~i', $template)) {
                continue;
            }
            return (string)$s['id'];
        }
        return null;
    }
}
