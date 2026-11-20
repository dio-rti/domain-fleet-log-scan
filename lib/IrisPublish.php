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
        $totalTimeout = (int)($run['total_timeout'] ?? $opt['total_timeout'] ?? 120);
        $connectTimeout = (int)($run['connect_timeout'] ?? $opt['connect_timeout'] ?? 15);
        $windowHours = (int)($run['window_hours'] ?? $opt['window_hours'] ?? 24);

        $roleRows = [];
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
        $groups = [];
        foreach ($flags as $f) {
            $note((string)$f['site'], (string)$f['role']);
            $l = $lvl($f['level'] ?? '');
            $count = (int)$f['count'];
            $totals[$l === 'fatal' ? 'fatals' : ($l === 'warning' ? 'warnings' : 'errors')] += $count;
            $fatal = ($f['flag'] ?? '') === 'new-fatal';
            $key = ($fatal ? 'fatal' : $l) . "\n" . (string)$f['template'];
            if (!isset($groups[$key])) {
                $groups[$key] = ['template' => (string)$f['template'], 'level' => $l, 'fatal' => $fatal, 'locs' => []];
            }
            $groups[$key]['fatal'] = $groups[$key]['fatal'] || $fatal;
            $groups[$key]['locs'][] = ['site' => (string)$f['site'], 'role' => (string)$f['role'], 'count' => $count];
        }
        $sigs = [];
        $urgent = [];
        $n = 0;
        foreach ($groups as $g) {
            $locs = [];
            $breakdown = [];
            $sum = 0;
            foreach ($g['locs'] as $loc) {
                if ($loc['site'] === '-' || $loc['site'] === '' || $loc['role'] === '-' || $loc['role'] === '') {
                    continue;
                }
                $locs[] = $loc['site'] . '/' . $loc['role'];
                $breakdown[$loc['site']][$loc['role']] = ($breakdown[$loc['site']][$loc['role']] ?? 0) + $loc['count'];
                $sum += $loc['count'];
            }
            $sigs[] = [
                'count' => $sum, 'level' => $g['level'],
                'severity' => $g['fatal'] ? 'critical' : ($g['level'] === 'warning' ? 'medium' : 'high'),
                'locations' => $locs ?: ['unknown/admin'],
                'signature' => $g['template'],
            ];
            $sev = $g['fatal'] ? 'critical' : ($g['level'] === 'warning' ? 'medium' : 'high');
            $row = [
                'id' => 'sig-' . substr(hash('sha256', $g['level'] . "\n" . $g['template']), 0, 12),
                'severity' => $sev,
                'title' => '"' . $g['template'] . '" errors came up ' . $sum . ' times',
                'count' => $sum,
            ];
            if ($breakdown) {
                $row['breakdown'] = $breakdown;
            }
            $detail = IrisPatterns::match(null, null, $g['template']);
            if ($detail !== null) {
                $row['detail'] = $detail;
            }
            $urgent[] = $row;
            $n++;
        }
        unset($n);
        usort($sigs, fn($a, $b) => $b['count'] <=> $a['count']);
        $sigRank = [];
        foreach ($sigs as $i => &$s) {
            $s = ['rank' => $i + 1] + $s;
            $sigRank[$s['signature']] = $i + 1;
        }
        unset($s);

        $gaps = [];
        $timedOut = [];
        foreach ($failures as $i => $f) {
            $site = (string)$f['site'];
            $role = (string)$f['role'];
            $st = (string)$f['status'];
            $note($site, $role);
            if (str_contains($st, 'timeout') && $site !== '-' && $role !== '-' && $role !== '') {
                if (isset($roleRows[$site][$role])) {
                    $roleRows[$site][$role]['status'] = 'timeout';
                    $roleRows[$site][$role]['error'] = ['type' => 'timeout', 'limit_seconds' => $totalTimeout];
                }
                $timedOut[] = $site . '/' . $role;
                continue;
            }
            $kind = 'visibility';
            if ($site !== '-' && $role !== '-' && isset($roleRows[$site][$role])) {
                $roleRows[$site][$role]['status'] = str_contains($st, 'reset') ? 'reset' : 'unreachable';
            }
            $gaps[] = ['type' => $kind, 'note' => 'scan failure: ' . $st] + ($role !== '-' && $role !== '' ? ['roles' => [$role]] : []);
            $urgent[] = ['id' => 'failure-' . $i, 'severity' => 'high', 'title' => 'Scan failure: ' . $st];
        }
        if ($timedOut) {
            $rolesOnly = array_map(static fn(string $sr): string => explode('/', $sr, 2)[1], $timedOut);
            $pattern = count(array_unique($rolesOnly)) === 1 ? IrisPatterns::match($rolesOnly[0], 'timeout', null) : null;
            $gaps[] = [
                'type' => 'timeout',
                'roles' => $timedOut,
                'note' => $pattern ?? ('Read timed out on ' . implode(', ', $timedOut) . '.'),
            ];
        }

        foreach ($run['quiet'] ?? [] as $q) {
            if (!is_array($q)) {
                continue;
            }
            $site = (string)($q['site'] ?? '');
            $role = (string)($q['role'] ?? '');
            $note($site, $role);
            if (!isset($roleRows[$site][$role])) {
                continue;
            }
            $epoch = $q['epoch'] ?? null;
            if (is_int($epoch) && $epoch > 0) {
                $dt = (new \DateTimeImmutable('@' . $epoch))->setTimezone(new \DateTimeZone('Asia/Manila'));
                $roleRows[$site][$role]['log_last_write_clock'] = [
                    'time' => $dt->format('Y-m-d\TH:i:sP'),
                    'timezone' => 'Asia/Manila',
                    'note' => 'stopped writing',
                ];
            } else {
                $roleRows[$site][$role]['log_last_write_clock'] = ['note' => 'last write time unknown'];
            }
        }

        $sevRank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'noise' => 4];
        usort($urgent, static function (array $a, array $b) use ($sevRank, $sigRank): int {
            $sa = $sevRank[$a['severity'] ?? ''] ?? 9;
            $sb = $sevRank[$b['severity'] ?? ''] ?? 9;
            if ($sa !== $sb) {
                return $sa <=> $sb;
            }
            $ca = (int)($a['count'] ?? 0);
            $cb = (int)($b['count'] ?? 0);
            if ($ca !== $cb) {
                return $cb <=> $ca;
            }
            $rankOf = static function (array $row) use ($sigRank): int {
                $title = (string)($row['title'] ?? '');
                foreach ($sigRank as $sig => $rank) {
                    if ($sig !== '' && str_contains($title, (string)$sig)) {
                        return $rank;
                    }
                }
                return PHP_INT_MAX;
            };
            return $rankOf($a) <=> $rankOf($b);
        });

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
        $rid = self::runId((string)($run['run_id'] ?? ''), $started);
        $region = self::region($siteIds, $opt);
        $executor = (string)($run['executor'] ?? 'fleet-log-scan');
        $job = [
            'job_id' => $region . '-log-scan-' . gmdate('Ymd', $now),
            'run_id' => $rid,
            'requested_by' => 'scheduler',
            'executor' => $executor,
        ];
        if (isset($run['model']) && is_string($run['model']) && $run['model'] !== '') {
            $job['model'] = $run['model'];
        }
        $doc = [
            'schema_version' => '1.0',
            'report_type' => 'fleet_log_scan',
            'run_type' => 'fleet_log_scan',
            'job' => $job,
            'scope' => [
                'region' => $region,
                'mode' => $fixtures ? 'fixtures' : 'read_only',
                'sites' => $siteIds,
                'window' => ['type' => preg_match('/^[a-z_]{1,40}$/', $mode) ? $mode : 'scan', 'hours' => $windowHours, 'end' => self::ts($now)],
            ],
            'timing' => [
                'started_at' => self::ts($started), 'finished_at' => self::ts(max($now, $started)),
                'duration_seconds' => max(0, $now - $started),
                'timezone_note' => 'Human clock is Asia/Manila.',
            ],
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
            'config' => [
                'connect_timeout_seconds' => $connectTimeout,
                'total_timeout_seconds' => $totalTimeout,
                'byte_cap_mb_per_file' => 0,
                'first_run_hours' => $windowHours,
            ],
            'safety' => [
                'live_enabled_after_run' => false, 'state_disabled_present' => false, 'webhook_env_present' => false,
                'launch_agent_present' => false, 'summary_model_used' => self::summaryUsed($run),
                'delivery' => 'none', 'ipv4_in_outputs' => 0, 'secrets_in_outputs' => 0, 'server_writes' => false, 'sudo_used' => false,
            ],
            'artifacts' => ['report_md' => null, 'tool_report' => $rid !== '' ? $rid . '.txt' : null],
            'suggested_fixes' => [],
        ];
        if (self::summaryUsed($run)) {
            $doc['ai_summary'] = $run['ai_summary'];
        }
        return self::finish(self::augment2($doc));
    }

    /** Keep a valid id. Otherwise emit YYYYMMDDTHHMMSSZ-hex from the start time. */
    private static function runId(string $rid, int $started): string
    {
        if (preg_match('/^[0-9]{8}T[0-9]{6}Z?-[0-9a-f]{4,12}$/', $rid) === 1) {
            return $rid;
        }
        $hex = substr(hash('sha256', $rid !== '' ? $rid : 'run'), 0, 8);
        return gmdate('Ymd\THis\Z', $started) . '-' . $hex;
    }

    /** The old digest's "summary ok" is not an Iris model attachment. */
    private static function summaryUsed(array $run): bool
    {
        $ai = $run['ai_summary'] ?? null;
        return is_array($ai)
            && ($ai['status'] ?? '') === 'ok'
            && ($ai['model'] ?? '') === 'grok-4.7-high'
            && is_string($ai['text'] ?? null)
            && $ai['text'] !== '';
    }

    /** Write the final document once. A later call returns those bytes. */
    public static function remember(string $path, array $doc): array
    {
        if (is_file($path)) {
            $saved = json_decode((string)file_get_contents($path), true);
            if (is_array($saved)) {
                return $saved;
            }
        }
        $dir = dirname($path);
        if (!is_dir($dir)) {
            Fs::ensureDir($dir);
        }
        $raw = json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        Fs::writeSecure($path, $raw);
        $again = json_decode($raw, true);
        return is_array($again) ? $again : $doc;
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
