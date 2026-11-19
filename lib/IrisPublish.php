<?php
declare(strict_types=1);

namespace Fls;

/**
 * Iris ingest v1 publisher (disabled unless --iris-publish). Builds or augments an ingest v1
 * document. Pure functions: no network, no file writes. Delivery goes through Webhook::post.
 */
final class IrisPublish
{
    private static int $dropped = 0;

    /** Quiet days skip the publisher unless the flag is on. */
    public static function postsOnQuietDay(bool $flag): bool
    {
        return $flag;
    }

    /** Number of string fields dropped by the tripwire in the last augment/fromRun call. */
    public static function dropped(): int
    {
        return self::$dropped;
    }

    public static function augment(array $sg): array
    {
        self::$dropped = 0;
        unset($sg['payload_hash']);
        $rt = $sg['report_type'] ?? null;
        $sg['run_type'] = in_array($rt, ['fleet_log_scan', 'version_check'], true) ? $rt : 'fleet_log_scan';

        if (!isset($sg['suggested_fixes']) || !is_array($sg['suggested_fixes'])) {
            $sg['suggested_fixes'] = self::rulesFixes($sg);
        }
        if (isset($sg['scope']) && is_array($sg['scope'])) {
            unset($sg['scope']['jump_alias']);
        }
        if (isset($sg['job']) && is_array($sg['job'])) {
            $rb = $sg['job']['requested_by'] ?? '';
            if (!is_string($rb) || $rb === '' || str_contains($rb, '@')) {
                $sg['job']['requested_by'] = 'scheduler';
            }
        }
        foreach (['report_md', 'tool_report'] as $k) {
            if (isset($sg['artifacts'][$k]) && is_string($sg['artifacts'][$k])) {
                $sg['artifacts'][$k] = self::base($sg['artifacts'][$k]);
            }
        }
        if (isset($sg['sites']) && is_array($sg['sites'])) {
            foreach ($sg['sites'] as $i => $s) {
                foreach ($s['roles'] ?? [] as $j => $r) {
                    foreach ($r['byte_cap_hits'] ?? [] as $h => $hit) {
                        if (isset($hit['file']) && is_string($hit['file'])) {
                            $sg['sites'][$i]['roles'][$j]['byte_cap_hits'][$h]['file'] = self::base($hit['file']);
                        }
                    }
                }
            }
        }
        foreach ($sg['top_signatures'] ?? [] as $i => $sig) {
            if (isset($sig['signature']) && is_string($sig['signature'])) {
                $sg['top_signatures'][$i]['signature'] = self::noSlash($sig['signature'], (string)($sig['level'] ?? 'note'));
            }
        }
        foreach ($sg['suggested_fixes'] as $i => $fx) {
            if (isset($fx['fix_text']) && is_string($fx['fix_text'])) {
                $sg['suggested_fixes'][$i]['fix_text'] = self::noSlash($fx['fix_text'], 'note');
            }
        }
        return self::finish($sg);
    }

    /** Minimal valid ingest v1 from what the run actually has. */
    public static function fromRun(array $run, array $opt, int $now): array
    {
        self::$dropped = 0;
        $flags = $run['flags'] ?? [];
        $failures = array_values($run['failures'] ?? []);
        $started = (int)($run['started'] ?? $now);
        $lvl = static fn($l) => in_array($l, ['error', 'warning', 'fatal'], true) ? $l : 'error';

        $roleRows = [];   // site => role => row
        $sitesSeen = [];
        $note = static function (string $site, string $role) use (&$roleRows, &$sitesSeen): void {
            if ($site === '-' || $site === '') {
                return;
            }
            $sitesSeen[$site] = true;
            if ($role !== '-' && $role !== '' && !isset($roleRows[$site][$role])) {
                $roleRows[$site][$role] = ['role' => $role, 'status' => 'ok', 'duration_seconds' => 0, 'checkpoint_saved' => false];
            }
        };
        if (!empty($opt['site']) && is_string($opt['site'])) {
            $sitesSeen[$opt['site']] = true;
        }
        $totals = ['errors' => 0, 'warnings' => 0, 'fatals' => 0, 'http_500_bursts' => 0];
        $sigs = [];
        $urgent = [];
        foreach ($flags as $f) {
            $note((string)$f['site'], (string)$f['role']);
            $l = $lvl($f['level'] ?? '');
            $totals[$l === 'fatal' ? 'fatals' : ($l === 'warning' ? 'warnings' : 'errors')] += (int)$f['count'];
            $fatal = ($f['flag'] ?? '') === 'new-fatal';
            $sigs[] = [
                'count' => (int)$f['count'], 'level' => $l,
                'severity' => $fatal ? 'critical' : ($l === 'warning' ? 'medium' : 'high'),
                'locations' => [$f['site'] . '/' . $f['role']],
                'signature' => (string)$f['template'],
            ];
            if ($fatal) {
                $urgent[] = ['id' => 'new-fatal-' . count($urgent), 'severity' => 'critical', 'title' => 'New fatal group', 'sites' => [(string)$f['site']], 'roles' => [(string)$f['role']], 'count' => (int)$f['count']];
            }
        }
        usort($sigs, fn($a, $b) => $b['count'] <=> $a['count']);
        foreach ($sigs as $i => &$s) {
            $s = ['rank' => $i + 1] + $s;
        }
        unset($s);

        $gaps = [];
        foreach ($failures as $i => $f) {
            $site = (string)$f['site'];
            $role = (string)$f['role'];
            $st = (string)$f['status'];
            $note($site, $role);
            $kind = str_contains($st, 'timeout') ? 'timeout' : 'visibility';
            if ($site !== '-' && $role !== '-' && isset($roleRows[$site][$role])) {
                $roleRows[$site][$role]['status'] = $kind === 'timeout' ? 'timeout' : (str_contains($st, 'reset') ? 'reset' : 'unreachable');
            }
            $gaps[] = ['type' => $kind, 'note' => 'scan failure: ' . $st] + ($role !== '-' ? ['roles' => [$role]] : []);
            $urgent[] = ['id' => 'failure-' . $i, 'severity' => 'high', 'title' => 'Scan failure: ' . $st];
        }

        $sites = [];
        $siteIds = array_map('strval', array_keys($sitesSeen));
        sort($siteIds, SORT_STRING);
        $failedRoles = 0;
        foreach ($siteIds as $sid) {
            $rows = array_values($roleRows[$sid] ?? []);
            $ok = count(array_filter($rows, fn($r) => $r['status'] === 'ok'));
            $failedRoles += count($rows) - $ok;
            $e = $w = 0;
            foreach ($flags as $f) {
                if ((string)$f['site'] === (string)$sid) {
                    $f['level'] === 'warning' ? $w += (int)$f['count'] : $e += (int)$f['count'];
                }
            }
            $sites[] = ['site_id' => (string)$sid, 'roles_total' => count($rows), 'roles_ok' => $ok, 'errors' => $e, 'warnings' => $w, 'roles' => $rows];
        }

        $failed = count($failures);
        $total = max((int)($run['servers'] ?? 0), 0);
        $fixtures = !empty($opt['fixtures']);
        $mode = (string)($run['mode'] ?? 'daily');
        $rid = (string)($run['run_id'] ?? '');
        $doc = [
            'schema_version' => '1.0',
            'report_type' => 'fleet_log_scan',
            'run_type' => 'fleet_log_scan',
            'job' => ['job_id' => $rid, 'run_id' => $rid, 'requested_by' => 'scheduler', 'executor' => 'fleet-log-scan'],
            'scope' => [
                'region' => self::region($siteIds, $opt),
                'mode' => $fixtures ? 'fixtures' : 'read_only',
                'sites' => $siteIds,
                'window' => ['type' => preg_match('/^[a-z_]{1,40}$/', $mode) ? $mode : 'scan', 'hours' => 0, 'end' => self::ts($now)],
            ],
            'timing' => ['started_at' => self::ts($started), 'finished_at' => self::ts(max($now, $started)), 'duration_seconds' => max(0, $now - $started)],
            'result' => [
                'status' => $failed ? 'partial' : 'ok', 'exit_code' => $failed ? 5 : 0,
                'roles_total' => $total, 'roles_ok' => max(0, $total - $failed), 'roles_failed' => $failed,
                'flagged_new_groups' => count($flags),
            ],
            'totals' => $totals,
            'sites' => $sites,
            'top_signatures' => $sigs,
            'urgent' => $urgent,
            'coverage_gaps' => $gaps,
            'config' => ['connect_timeout_seconds' => 0, 'total_timeout_seconds' => 0, 'byte_cap_mb_per_file' => 0, 'first_run_hours' => 0],
            'safety' => [
                'live_enabled_after_run' => false, 'state_disabled_present' => false, 'webhook_env_present' => false,
                'launch_agent_present' => false, 'summary_model_used' => ($run['summary_status'] ?? '') === 'summary ok',
                'delivery' => 'none', 'ipv4_in_outputs' => 0, 'secrets_in_outputs' => 0, 'server_writes' => false, 'sudo_used' => false,
            ],
            'artifacts' => ['report_md' => null, 'tool_report' => $rid !== '' ? $rid . '.txt' : null],
            'suggested_fixes' => [],
        ];
        return self::finish(self::augment2($doc));
    }

    /** Slash-prefix and path rules for a freshly built document, without resetting the drop counter. */
    private static function augment2(array $doc): array
    {
        foreach ($doc['top_signatures'] as $i => $sig) {
            $doc['top_signatures'][$i]['signature'] = self::noSlash($sig['signature'], $sig['level']);
        }
        return $doc;
    }

    private static function region(array $siteIds, array $opt): string
    {
        $map = ['11' => 'sg', '10' => 'jp', '30' => 'vertex'];
        $ids = $siteIds;
        if (!empty($opt['site']) && is_string($opt['site'])) {
            array_unshift($ids, $opt['site']);
        }
        foreach ($ids as $id) {
            $p = substr((string)$id, 0, 2);
            if (isset($map[$p])) {
                return $map[$p];
            }
        }
        if ($ids) {
            return !empty($opt['region']) && preg_match('/^[a-z]{2,8}$/', (string)$opt['region']) ? (string)$opt['region'] : 'unknown';
        }
        return 'sg';
    }

    private static function ts(int $t): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $t);
    }

    private static function base(string $p): string
    {
        return (str_contains($p, '/') || str_starts_with($p, '~')) ? basename(str_replace('\\', '/', $p)) : $p;
    }

    private static function noSlash(string $s, string $word): string
    {
        return str_starts_with($s, '/') ? ($word !== '' ? $word : 'note') . ': ' . $s : $s;
    }

    /** @return list<array<string,mixed>> */
    private static function rulesFixes(array $sg): array
    {
        $out = [];
        $add = static function (string $ref, string $sev, string $text, array $sites, array $roles) use (&$out): void {
            $aff = [];
            foreach ($sites as $s) {
                $aff[] = ['site_id' => (string)$s, 'roles' => array_values(array_map('strval', $roles))];
            }
            $out[] = ['issue_ref' => $ref, 'severity' => $sev, 'confidence' => 0.5, 'fix_text' => $text, 'affected' => $aff, 'source' => 'rule'];
        };
        foreach ($sg['coverage_gaps'] ?? [] as $i => $g) {
            if (!empty($g['fix']) && is_string($g['fix'])) {
                $add('gap-' . $i, 'low', $g['fix'], [], []);
            }
        }
        foreach ($sg['urgent'] ?? [] as $u) {
            if (!empty($u['title']) && is_string($u['title']) && !empty($u['id'])) {
                $add((string)$u['id'], in_array($u['severity'] ?? '', ['critical', 'high', 'medium', 'low', 'noise'], true) ? $u['severity'] : 'high', $u['title'], $u['sites'] ?? [], $u['roles'] ?? []);
            }
        }
        return $out;
    }

    /** Tripwire-drop strings, then set payload_hash. */
    private static function finish(array $doc): array
    {
        $doc = self::sanitize($doc, '');
        // A row that lost its required text is dropped whole (it would fail ingest validation).
        foreach (['top_signatures' => 'signature', 'suggested_fixes' => 'fix_text'] as $list => $req) {
            if (isset($doc[$list]) && is_array($doc[$list])) {
                $doc[$list] = array_values(array_filter($doc[$list], fn($r) => is_array($r) && isset($r[$req])));
            }
        }
        unset($doc['payload_hash']);
        $doc['payload_hash'] = self::hash($doc);
        return $doc;
    }

    /** Identity fields defined by the ingest pattern (run id, timestamps) are exempt from the tripwire. */
    private static function exempt(string $ptr): bool
    {
        return $ptr === '/schema_version' || $ptr === '/artifacts/tool_report' || str_starts_with($ptr, '/job/') || str_starts_with($ptr, '/timing/') || $ptr === '/scope/window/end';
    }

    private static function sanitize(array $a, string $ptr): array
    {
        $isList = array_is_list($a);
        $out = [];
        foreach ($a as $k => $v) {
            $p = $ptr . '/' . $k;
            if (is_array($v)) {
                $v = self::sanitize($v, $p);
            } elseif (is_string($v) && !self::exempt($p) && !preg_match('/^\d{8}T\d{6}Z?-[0-9a-f]{4,12}(?:\.txt|\.md)?$/', $v) && Redact::tripwire($v) !== null) {
                self::$dropped++;
                continue;
            }
            $isList ? $out[] = $v : $out[$k] = $v;
        }
        return $out;
    }

    public static function canonical(mixed $v): string
    {
        return json_encode(self::sortKeys($v), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function sortKeys(mixed $v): mixed
    {
        if (!is_array($v)) {
            return $v;
        }
        if (array_is_list($v)) {
            return array_map([self::class, 'sortKeys'], $v);
        }
        $keys = array_keys($v);
        usort($keys, fn($x, $y) => strcmp((string)$x, (string)$y));
        $o = [];
        foreach ($keys as $k) {
            $o[$k] = self::sortKeys($v[$k]);
        }
        return $o;
    }

    public static function hash(array $doc): string
    {
        unset($doc['payload_hash']);
        return hash('sha256', self::canonical($doc));
    }
}
