<?php
declare(strict_types=1);

namespace Fls;

/**
 * Iris ingest v1 publisher (disabled unless --iris-publish). Builds or augments an ingest v1
 * document. Pure functions: no network, no file writes. Delivery goes through Webhook::post.
 */
final class IrisPublish
{
    private const BODY_LIMIT = 1048576 - 40960;
    private const SEV = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'noise' => 4];
    private const GAP = ['timeout' => 0, 'visibility' => 1, 'byte_cap' => 2, 'version' => 3];
    private const LISTS = ['top_signatures', 'urgent', 'suggested_fixes', 'coverage_gaps'];

    private static int $dropped = 0;
    private static array $capStats = [];

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

    /** What the last cap call kept and dropped: orig/kept per list plus per-kind drop counts. */
    public static function capStats(): array
    {
        return self::$capStats;
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
            'artifacts' => ['report_md' => null, 'tool_report' => null],
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
    public static function remember(string $path, array $doc, bool $replace = false): array
    {
        if (!$replace && is_file($path)) {
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

    /** Tripwire-drop strings, cap the lists, then set payload_hash and fit the body size. */
    private static function finish(array $doc): array
    {
        $doc = self::sanitize($doc, '');
        // Urgent rows with a title but no usable id get a deterministic digit-free id, so they survive the cap.
        if (isset($doc['urgent']) && is_array($doc['urgent'])) {
            $safe = static fn($id): bool => is_string($id) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $id) === 1 && !preg_match('/\d{7}/', $id);
            $used = [];
            foreach ($doc['urgent'] as $i => $r) {
                if (is_array($r) && isset($r['title']) && $safe($r['id'] ?? null) && !isset($used[$r['id']])) {
                    $used[$r['id']] = true;
                    $doc['urgent'][$i]['_keep'] = true;
                }
            }
            foreach ($doc['urgent'] as $i => $r) {
                if (!is_array($r) || !isset($r['title'])) {
                    continue;
                }
                if (isset($r['_keep'])) {
                    unset($doc['urgent'][$i]['_keep']);
                    continue;
                }
                $h = hash('sha256', json_encode([$r['severity'] ?? null, $r['title'], $r['count'] ?? null]));
                $id = 'u' . substr(strtr($h, '0123456789', 'ghijklmnop'), 0, 40);
                while (isset($used[$id])) {
                    $id .= 'x';
                }
                $used[$id] = true;
                $doc['urgent'][$i]['id'] = $id;
            }
        }
        // A row that lost its required text is dropped whole (it would fail ingest validation).
        $need = ['top_signatures' => ['signature'], 'suggested_fixes' => ['fix_text'], 'urgent' => ['id', 'title']];
        foreach ($need as $list => $keys) {
            if (isset($doc[$list]) && is_array($doc[$list])) {
                $doc[$list] = array_values(array_filter($doc[$list], fn($r) => is_array($r) && count(array_filter($keys, fn($k) => isset($r[$k]))) === count($keys)));
            }
        }
        $doc = self::cap($doc);
        unset($doc['payload_hash']);
        $doc['payload_hash'] = self::hash($doc);
        return self::fit($doc);
    }

    private static function cap(array $doc): array
    {
        $st = ['orig' => [], 'kept' => [], 'n' => array_fill_keys(['loc', 'role', 'hit', 'site', 'cut', 'aff'], 0), 'base' => null];
        $n = &$st['n'];
        $n['cut'] = self::cutText($doc);
        $base = $doc['result']['flagged_note'] ?? null;
        $st['base'] = is_string($base) ? $base : null;
        foreach (self::LISTS as $l) {
            $st['orig'][$l] = count(self::rows($doc, $l));
        }
        $keep = self::capScope($doc, $n);
        self::capSites($doc, $keep, $n);
        $had = array_filter(self::LISTS, fn($l) => array_key_exists($l, $doc));
        $new = [
            'top_signatures' => self::capSigs($doc, $keep, $n),
            'urgent' => self::capUrgent($doc),
        ];
        $doc['urgent'] = $new['urgent'];
        $new['suggested_fixes'] = self::capFixes($doc, $keep, $n);
        $new['coverage_gaps'] = self::capGaps($doc);
        foreach (self::LISTS as $l) {
            $st['kept'][$l] = count($new[$l]);
            if (in_array($l, $had, true)) {
                $doc[$l] = $new[$l];
            } else {
                unset($doc[$l]);
            }
        }
        unset($n);
        self::$capStats = $st;
        return self::record($doc, $st);
    }

    /** @return list<mixed> */
    private static function rows(array $doc, string $key): array
    {
        return is_array($doc[$key] ?? null) ? array_values($doc[$key]) : [];
    }

    private static function sevOf(mixed $row): int
    {
        return self::SEV[is_array($row) ? (string)($row['severity'] ?? '') : ''] ?? 9;
    }

    private static function cutFields(mixed &$row, array $limits): int
    {
        $n = 0;
        foreach ($limits as $k => $max) {
            if (is_array($row) && isset($row[$k]) && is_string($row[$k]) && mb_strlen($row[$k]) > $max) {
                $row[$k] = mb_substr($row[$k], 0, $max);
                $n++;
            }
        }
        return $n;
    }

    /** Free-text fields are cut to their schema maxLength. Identifier fields are never cut. */
    private static function cutText(array &$doc): int
    {
        $n = 0;
        $top = ['result' => ['flagged_note' => 500, 'exit_reason' => 500], 'timing' => ['timezone_note' => 200]];
        foreach ($top as $k => $lim) {
            $n += isset($doc[$k]) ? self::cutFields($doc[$k], $lim) : 0;
        }
        $lists = [
            'top_signatures' => ['signature' => 2000],
            'urgent' => ['title' => 200, 'detail' => 2000, 'caveat' => 500],
            'suggested_fixes' => ['fix_text' => 2000],
            'coverage_gaps' => ['note' => 1000, 'fix' => 1000],
        ];
        foreach ($lists as $list => $lim) {
            foreach (array_keys(self::rows($doc, $list)) as $i) {
                $n += self::cutFields($doc[$list][$i], $lim);
            }
        }
        foreach (array_keys(self::rows($doc, 'sites')) as $i) {
            foreach (array_keys(self::rows($doc['sites'][$i] ?? [], 'roles')) as $j) {
                $n += self::cutRole($doc['sites'][$i]['roles'][$j]);
            }
        }
        if (isset($doc['artifacts']['tool_report']) && is_string($doc['artifacts']['tool_report']) && preg_match('/[0-9]{7,}/', $doc['artifacts']['tool_report']) === 1) {
            $doc['artifacts']['tool_report'] = null;
            $n++;
        }
        return $n;
    }

    private static function cutRole(mixed &$role): int
    {
        $n = 0;
        foreach (['error' => ['detail' => 500], 'log_last_write_clock' => ['note' => 200]] as $k => $lim) {
            $n += is_array($role) && isset($role[$k]) ? self::cutFields($role[$k], $lim) : 0;
        }
        return $n;
    }

    /** @return ?list<string> the kept scope.sites, or null when the document has none */
    private static function capScope(array &$doc, array &$n): ?array
    {
        $sites = $doc['scope']['sites'] ?? null;
        if (!is_array($sites)) {
            return null;
        }
        $sites = array_values($sites);
        if (count($sites) > 500) {
            sort($sites, SORT_STRING);
            $n['site'] += count($sites) - 500;
            $sites = array_slice($sites, 0, 500);
            $doc['scope']['sites'] = $sites;
        }
        return array_map('strval', $sites);
    }

    private static function capSites(array &$doc, ?array $keep, array &$n): void
    {
        if ($keep === null || !is_array($doc['sites'] ?? null)) {
            return;
        }
        $pos = array_flip($keep);
        $rows = array_values(array_filter($doc['sites'], fn($s) => is_array($s) && isset($s['site_id']) && is_scalar($s['site_id']) && isset($pos[(string)$s['site_id']])));
        $n['site'] += count($doc['sites']) - count($rows);
        usort($rows, fn($a, $b) => $pos[(string)$a['site_id']] <=> $pos[(string)$b['site_id']]);
        if (count($rows) > 500) {
            $n['site'] += count($rows) - 500;
            $rows = array_slice($rows, 0, 500);
        }
        foreach ($rows as $i => $site) {
            $rows[$i] = self::capRoles($site, $n);
        }
        $doc['sites'] = $rows;
    }

    private static function capRoles(array $site, array &$n): array
    {
        if (!is_array($site['roles'] ?? null)) {
            return $site;
        }
        $roles = array_values($site['roles']);
        if (count($roles) > 50) {
            usort($roles, fn($a, $b) => [(($a['status'] ?? '') === 'ok') ? 1 : 0, (string)($a['role'] ?? '')] <=> [(($b['status'] ?? '') === 'ok') ? 1 : 0, (string)($b['role'] ?? '')]);
            $n['role'] += count($roles) - 50;
            $roles = array_slice($roles, 0, 50);
        }
        foreach ($roles as $j => $role) {
            if (is_array($role) && is_array($role['byte_cap_hits'] ?? null) && count($role['byte_cap_hits']) > 50) {
                $hits = array_values($role['byte_cap_hits']);
                usort($hits, fn($a, $b) => [-(float)($a['skipped_mb'] ?? 0), (string)($a['file'] ?? '')] <=> [-(float)($b['skipped_mb'] ?? 0), (string)($b['file'] ?? '')]);
                $n['hit'] += count($hits) - 50;
                $roles[$j]['byte_cap_hits'] = array_slice($hits, 0, 50);
            }
        }
        $site['roles'] = $roles;
        return $site;
    }

    /** @return list<array<string,mixed>> */
    private static function capSigs(array $doc, ?array $keep, array &$n): array
    {
        $pos = $keep === null ? null : array_flip($keep);
        $rows = [];
        foreach (self::rows($doc, 'top_signatures') as $sig) {
            $sig = self::capLocations($sig, $pos, $n);
            if ($sig !== null) {
                $rows[] = $sig;
            }
        }
        usort($rows, fn($a, $b) => [-(int)($a['count'] ?? 0), self::sevOf($a), (string)$a['signature'], (string)($a['level'] ?? '')] <=> [-(int)($b['count'] ?? 0), self::sevOf($b), (string)$b['signature'], (string)($b['level'] ?? '')]);
        $rows = array_slice(self::uniqueSigs($rows), 0, 500);
        return self::renumber($rows);
    }

    private static function capLocations(mixed $sig, ?array $pos, array &$n): ?array
    {
        if (!is_array($sig)) {
            return null;
        }
        $locs = is_array($sig['locations'] ?? null) ? array_values($sig['locations']) : [];
        $before = count($locs);
        if ($pos !== null) {
            $locs = array_values(array_filter($locs, fn($l) => is_string($l) && isset($pos[explode('/', $l, 2)[0]])));
        }
        $locs = array_slice($locs, 0, 500);
        $n['loc'] += $before - count($locs);
        $sig['locations'] = $locs;
        return $locs ? $sig : null;
    }

    /** Drop a later row whose level + signature repeats an earlier one. */
    private static function uniqueSigs(array $rows): array
    {
        $seen = [];
        $out = [];
        foreach ($rows as $r) {
            $k = (string)($r['level'] ?? '') . "\n" . $r['signature'];
            if (!isset($seen[$k])) {
                $seen[$k] = true;
                $out[] = $r;
            }
        }
        return $out;
    }

    private static function renumber(array $rows): array
    {
        foreach ($rows as $i => $r) {
            $rows[$i]['rank'] = $i + 1;
        }
        return $rows;
    }

    private static function capUrgent(array $doc): array
    {
        $rows = array_values(array_filter(self::rows($doc, 'urgent'), 'is_array'));
        usort($rows, fn($a, $b) => [self::sevOf($a), -(int)($a['count'] ?? 0), (string)$a['id']] <=> [self::sevOf($b), -(int)($b['count'] ?? 0), (string)$b['id']]);
        return array_slice($rows, 0, 200);
    }

    private static function capFixes(array $doc, ?array $keep, array &$n): array
    {
        $ids = array_flip(array_map(fn($u) => (string)$u['id'], self::rows($doc, 'urgent')));
        $pos = $keep === null ? null : array_flip($keep);
        $rows = array_values(array_filter(self::rows($doc, 'suggested_fixes'), 'is_array'));
        foreach ($rows as $i => $fx) {
            $rows[$i] = self::capAffected($fx, $pos, $n);
        }
        $pref = fn($f) => (isset($ids[(string)($f['issue_ref'] ?? '')]) || str_starts_with((string)($f['issue_ref'] ?? ''), 'gap-')) ? 0 : 1;
        usort($rows, fn($a, $b) => [$pref($a), self::sevOf($a), -(float)($a['confidence'] ?? 0), (string)($a['issue_ref'] ?? '')] <=> [$pref($b), self::sevOf($b), -(float)($b['confidence'] ?? 0), (string)($b['issue_ref'] ?? '')]);
        return array_slice($rows, 0, 200);
    }

    private static function capAffected(array $fx, ?array $pos, array &$n): array
    {
        if (!is_array($fx['affected'] ?? null)) {
            return $fx;
        }
        $aff = array_values($fx['affected']);
        $before = count($aff);
        if ($pos !== null) {
            $aff = array_values(array_filter($aff, fn($a) => is_array($a) && isset($a['site_id']) && is_scalar($a['site_id']) && isset($pos[(string)$a['site_id']])));
        }
        usort($aff, fn($a, $b) => strcmp((string)($a['site_id'] ?? ''), (string)($b['site_id'] ?? '')));
        $aff = array_slice($aff, 0, 500);
        $n['aff'] += $before - count($aff);
        $fx['affected'] = $aff;
        return $fx;
    }

    private static function capGaps(array $doc): array
    {
        $rows = array_values(array_filter(self::rows($doc, 'coverage_gaps'), 'is_array'));
        usort($rows, fn($a, $b) => (self::GAP[(string)($a['type'] ?? '')] ?? 9) <=> (self::GAP[(string)($b['type'] ?? '')] ?? 9));
        return array_slice($rows, 0, 200);
    }

    private static function changed(array $st): bool
    {
        foreach (self::LISTS as $l) {
            if ($st['kept'][$l] < $st['orig'][$l]) {
                return true;
            }
        }
        return array_sum($st['n']) > 0;
    }

    /** One fixed sentence from the pre-cap totals. No run data in it. */
    private static function sentence(array $st): string
    {
        [$o, $k, $n] = [$st['orig'], $st['kept'], $st['n']];
        $s = 'Iris caps: kept ' . $k['top_signatures'] . ' of ' . $o['top_signatures'] . ' signatures, ' . $k['urgent'] . ' of ' . $o['urgent'] . ' urgent';
        if ($k['suggested_fixes'] < $o['suggested_fixes']) {
            $s .= ', kept ' . $k['suggested_fixes'] . ' of ' . $o['suggested_fixes'] . ' fixes';
        }
        if ($k['coverage_gaps'] < $o['coverage_gaps']) {
            $s .= ', kept ' . $k['coverage_gaps'] . ' of ' . $o['coverage_gaps'] . ' gaps';
        }
        foreach (['loc' => 'dropped %d locations', 'role' => 'dropped %d roles', 'hit' => 'dropped %d byte-cap hits', 'site' => 'dropped %d sites', 'cut' => 'truncated %d fields'] as $key => $fmt) {
            $s .= $n[$key] > 0 ? ', ' . sprintf($fmt, $n[$key]) : '';
        }
        return $s . '.';
    }

    /** Write groups_recorded and flagged_note, only when this call changed something. */
    private static function record(array $doc, array $st): array
    {
        if (!self::changed($st) || !is_array($doc['result'] ?? null)) {
            return $doc;
        }
        $base = (string)$st['base'];
        $new = self::sentence($st);
        $doc['result']['flagged_note'] = $base === '' ? $new : (mb_strlen($base . ' ' . $new) <= 500 ? $base . ' ' . $new : $base);
        if ($st['kept']['top_signatures'] < $st['orig']['top_signatures']) {
            $doc['result']['groups_recorded'] = $st['orig']['top_signatures'];
        }
        return $doc;
    }

    private static function bodySize(array $doc): int
    {
        return strlen((string)json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /** Drop one chunk from the end of sites: byte-cap hits, then roles, then the site itself. False when nothing is left. */
    private static function dropSiteChunk(array &$doc, array &$n): bool
    {
        if (!is_array($doc['sites'] ?? null) || !$doc['sites']) {
            return false;
        }
        $chunk = fn(int $c): int => max(1, (int)ceil($c / 10));
        $sites = array_keys($doc['sites']);
        for ($a = count($sites) - 1; $a >= 0; $a--) {
            $si = $sites[$a];
            if (!is_array($doc['sites'][$si]['roles'] ?? null)) {
                continue;
            }
            $roles = array_keys($doc['sites'][$si]['roles']);
            for ($b = count($roles) - 1; $b >= 0; $b--) {
                $ri = $roles[$b];
                $hits = $doc['sites'][$si]['roles'][$ri]['byte_cap_hits'] ?? null;
                if (is_array($hits) && $hits) {
                    $k = $chunk(count($hits));
                    $doc['sites'][$si]['roles'][$ri]['byte_cap_hits'] = array_slice(array_values($hits), 0, count($hits) - $k);
                    $n['hit'] += $k;
                    return true;
                }
            }
        }
        for ($a = count($sites) - 1; $a >= 0; $a--) {
            $si = $sites[$a];
            $roles = $doc['sites'][$si]['roles'] ?? null;
            if (is_array($roles) && $roles) {
                $k = $chunk(count($roles));
                $doc['sites'][$si]['roles'] = array_slice(array_values($roles), 0, count($roles) - $k);
                $n['role'] += $k;
                return true;
            }
        }
        $last = array_pop($doc['sites']);
        $n['site']++;
        $id = is_array($last) && isset($last['site_id']) && is_scalar($last['site_id']) ? (string)$last['site_id'] : null;
        if ($id !== null && is_array($doc['scope']['sites'] ?? null)) {
            $doc['scope']['sites'] = array_values(array_filter($doc['scope']['sites'], fn($s) => (string)$s !== $id));
        }
        return true;
    }

    /** Drop items from the end until the body fits under the limit; rehash every round. */
    private static function fit(array $doc): array
    {
        $st = self::$capStats;
        while (self::bodySize($doc) > self::BODY_LIMIT) {
            $list = null;
            foreach (self::LISTS as $l) {
                if (is_array($doc[$l] ?? null) && $doc[$l]) {
                    $list = $l;
                    break;
                }
            }
            if ($list === null) {
                if (!self::dropSiteChunk($doc, $st['n'])) {
                    break;
                }
            } else {
                $doc[$list] = array_slice($doc[$list], 0, count($doc[$list]) - max(1, (int)ceil(count($doc[$list]) / 10)));
                if ($list === 'top_signatures') {
                    $doc[$list] = self::renumber($doc[$list]);
                }
                $st['kept'][$list] = count($doc[$list]);
            }
            $doc = self::record($doc, $st);
            unset($doc['payload_hash']);
            $doc['payload_hash'] = self::hash($doc);
        }
        self::$capStats = $st;
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

    /** A summary 422 is the only failure that is posted again, once, as skipped. */
    public static function summaryRejected(array $result): bool
    {
        if ((int)($result['code'] ?? 0) !== 422) {
            return false;
        }
        $body = $result['body'] ?? '';
        $json = is_array($body) ? $body : json_decode((string)$body, true);
        if (!is_array($json)) {
            return false;
        }
        $violations = $json['violations'] ?? [];
        if (!is_array($violations)) {
            return false;
        }
        foreach ($violations as $v) {
            if (!is_array($v)) {
                continue;
            }
            $ptr = (string)($v['pointer'] ?? '');
            $rule = (string)($v['rule'] ?? $v['class'] ?? '');
            if (str_starts_with($ptr, '/ai_summary') || $rule === 'summary_untraced') {
                return true;
            }
        }
        return false;
    }

    public static function asSkipped(array $doc): array
    {
        $doc['ai_summary'] = ['status' => 'skipped', 'text' => null, 'model' => null];
        if (!isset($doc['safety']) || !is_array($doc['safety'])) {
            $doc['safety'] = [];
        }
        $doc['safety']['summary_model_used'] = false;
        unset($doc['payload_hash']);
        $doc['payload_hash'] = self::hash($doc);
        return $doc;
    }

    /** @param callable(array): array{code:int,body:mixed} $client */
    public static function deliver(string $path, array $doc, callable $client): array
    {
        $sent = self::remember($path, $doc);
        $first = $client($sent);
        if (!self::summaryRejected($first)) {
            return ['posts' => 1, 'result' => $first, 'doc' => $sent];
        }
        $sent = self::remember($path, self::asSkipped($sent), true);
        return ['posts' => 2, 'result' => $client($sent), 'doc' => $sent];
    }
}

