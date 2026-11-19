<?php
declare(strict_types=1);

namespace Fls;

/**
 * Site discovery through Dio's `global` CLI (live GA API GETs), with config include/exclude.
 * Only site ids leave this class. global's stderr is never echoed (it may carry URLs).
 */
final class SiteSource
{
    public array $notes = [];
    public string $source = 'none';
    /** True when at least one configured region failed or returned an empty list while another succeeded. */
    public bool $partial = false;

    public function __construct(private array $cfg) {}

    /** Parse `global site list --json` output (tolerant to shape) or plain text. @return string[] */
    public static function parseSiteIds(string $out): array
    {
        $ids = [];
        $j = json_decode($out, true);
        if (is_array($j)) {
            foreach (self::rows($j, ['sites', 'data', 'items', 'results']) as $row) {
                if (is_array($row)) {
                    $v = $row['site_id'] ?? $row['siteId'] ?? $row['id'] ?? null;
                } else {
                    $v = $row;
                }
                if (is_scalar($v) && preg_match('/^\d{5}$/', (string)$v)) {
                    $ids[] = (string)$v;
                }
            }
        } else {
            foreach (preg_split('/\R/', $out) as $line) {
                if (preg_match('/^\s*(\d{5})\b/', $line, $m)) {
                    $ids[] = $m[1];
                }
            }
        }
        $ids = array_values(array_unique($ids));
        sort($ids);
        return $ids;
    }

    public static function rows(array $j, array $keys): array
    {
        if (array_is_list($j)) {
            return $j;
        }
        foreach ($keys as $k) {
            if (isset($j[$k]) && is_array($j[$k])) {
                return self::rows($j[$k], $keys);
            }
        }
        return [];
    }

    /** @return string[] site ids after include/exclude (exclude wins). */
    public function discover(bool $allowNetwork): array
    {
        $g = $this->cfg['global_cli'];
        $found = [];
        $ok = false;
        if (!$allowNetwork) {
            $this->notes[] = 'site list: global CLI not called (no-network mode); used config include list';
        } elseif (!$g['enabled']) {
            $this->notes[] = 'site list: global CLI disabled in config; used config include list';
        } elseif (!is_file($g['bin']) || !is_executable($g['bin'])) {
            $this->notes[] = 'site list: global CLI missing; used config include list';
        } else {
            $errs = [];
            foreach ($g['profiles'] as $region => $profile) {
                if (!preg_match('/^[a-z0-9_-]+$/', (string)$profile)) {
                    continue;
                }
                $r = Proc::run([$g['bin'], '--profile', $profile, '--json', '--quiet', '--no-color', 'site', 'list', '--status', '1', '--all'], '', (int)$g['timeout']);
                if ($r['exit'] !== 0) {
                    $errs[] = $region . ' exit ' . $r['exit'];
                    continue;
                }
                $ids = self::parseSiteIds($r['stdout']);
                if (!$ids) {
                    $errs[] = $region . ' empty';
                    continue;
                }
                $ok = true;
                $found = array_merge($found, $ids);
            }
            if (!$ok) {
                $this->notes[] = 'site list: global CLI gave no usable list (' . implode(', ', $errs) . '); used config include list';
            } elseif ($errs) {
                $this->partial = true;
                $this->notes[] = 'site list: global CLI partial (' . implode(', ', $errs) . ')';
            }
        }
        $this->source = $ok ? 'global-cli' : 'config-include';
        $all = array_merge($found, $this->cfg['sites']['include']);
        $all = array_values(array_unique(array_filter($all, fn($s) => Config::regionOf($this->cfg, $s) !== null)));
        $all = array_values(array_diff($all, $this->cfg['sites']['exclude']));
        sort($all);
        return $all;
    }
}

/**
 * Servers of one site, by role. Addresses stay in memory only and are never printed, logged or stored.
 */
final class ServerList
{
    /** @var array<string,array{role:string,class:string,addr:string}> role => server */
    public array $servers = [];
    public ?string $problem = null;

    public static function classToRole(string $class): ?string
    {
        return match (strtoupper(trim($class))) {
            'S', 'SERVICE' => 'service',
            'A', 'ADMIN' => 'admin',
            'DB' => 'db',
            'DS' => 'ds',
            default => null,
        };
    }

    /** Stable id from a server-list row. Never an address: dots and colons are rejected. */
    public static function stableId(array $row): ?string
    {
        $id = $row['id'] ?? $row['server_id'] ?? $row['serverId'] ?? null;
        if (is_int($id)) {
            $id = (string)$id;
        }
        if (!is_string($id) || !preg_match('/^[0-9A-Za-z_-]{1,32}$/', $id)) {
            return null;
        }
        return $id;
    }

    /**
     * Roles from global `server list --json`.
     * When every server of a class has a distinct id, the role is class+id and does not
     * move if a peer with a lower-sorting address is added. Without ids, ordinals use
     * numeric-aware address order (a single db/admin/ds stays unsuffixed).
     */
    public static function fromGlobalOutput(string $out): self
    {
        $sl = new self();
        $j = json_decode($out, true);
        $by = [];
        if (is_array($j)) {
            foreach (SiteSource::rows($j, ['servers', 'data', 'items', 'results']) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $addr = $row['ip'] ?? $row['server_ip'] ?? $row['address'] ?? $row['host'] ?? null;
                $cls = $row['class'] ?? $row['server_class'] ?? $row['classification'] ?? $row['type'] ?? '';
                $role = self::classToRole((string)$cls);
                if (!is_string($addr) || !preg_match('/^[0-9A-Za-z.:-]{3,253}$/', $addr) || $role === null) {
                    continue;
                }
                $by[$role][] = ['addr' => $addr, 'id' => self::stableId($row)];
            }
        }
        foreach ($by as $role => $items) {
            // Drop duplicate addresses within the class, keeping the first id.
            $uniq = [];
            foreach ($items as $it) {
                if (!isset($uniq[$it['addr']])) {
                    $uniq[$it['addr']] = $it;
                }
            }
            $items = array_values($uniq);
            $seen = [];
            $stable = $items !== [];
            foreach ($items as $it) {
                if ($it['id'] === null || isset($seen[$it['id']])) {
                    $stable = false;
                    break;
                }
                $seen[$it['id']] = true;
            }
            if ($stable) {
                usort($items, static fn($a, $b) => strnatcmp((string)$a['id'], (string)$b['id']));
            } else {
                usort($items, static fn($a, $b) => strnatcmp($a['addr'], $b['addr']));
            }
            $n = count($items);
            foreach ($items as $i => $it) {
                if ($stable) {
                    $name = $role . $it['id'];
                } else {
                    $name = ($role === 'service' || $n > 1) ? $role . ($i + 1) : $role;
                }
                $sl->servers[$name] = ['role' => $name, 'class' => $role === 'ds' ? 'db' : $role, 'addr' => $it['addr']];
            }
        }
        $hasService = (bool)array_filter($sl->servers, fn($s) => $s['class'] === 'service');
        $hasDb = (bool)array_filter($sl->servers, fn($s) => $s['class'] === 'db');
        if (!$hasService || !$hasDb) {
            $sl->problem = 'list unreadable';
        }
        return $sl;
    }

    public static function fromGlobal(array $cfg, string $site, string $region): self
    {
        $g = $cfg['global_cli'];
        $profile = $g['profiles'][$region] ?? null;
        if (!$g['enabled'] || !is_file($g['bin']) || $profile === null) {
            $sl = new self();
            $sl->problem = 'list unreadable (global CLI unavailable)';
            return $sl;
        }
        $r = Proc::run([$g['bin'], '--profile', $profile, '--json', '--quiet', '--no-color', 'server', 'list', $site], '', (int)$g['timeout']);
        if ($r['exit'] !== 0) {
            $sl = new self();
            $sl->problem = 'list unreadable (global exit ' . $r['exit'] . ')';
            return $sl;
        }
        return self::fromGlobalOutput($r['stdout']);
    }

    /** Fixture layout: <fixtures>/<site>/<role>/ */
    public static function fromFixtures(string $dir, string $site): self
    {
        $sl = new self();
        foreach (glob($dir . '/' . $site . '/*', GLOB_ONLYDIR) ?: [] as $d) {
            $name = basename($d);
            if (!preg_match('/^(service|admin|db|ds)\d*$/', $name, $m)) {
                continue;
            }
            $sl->servers[$name] = ['role' => $name, 'class' => $m[1] === 'ds' ? 'db' : $m[1], 'addr' => '', 'dir' => $d];
        }
        ksort($sl->servers);
        if (!$sl->servers) {
            $sl->problem = 'list unreadable';
        }
        return $sl;
    }
}
