<?php
declare(strict_types=1);

namespace Fls;

final class Runner
{
    private string $runId;
    private string $scratch;
    private int $now;
    private array $out = [];

    public function __construct(private array $cfg, private array $opt)
    {
        $this->now = $opt['now'] ?? time();
        $this->runId = Tz::manila($this->now, 'Ymd\THis') . '-' . bin2hex(random_bytes(3));
        $this->scratch = $cfg['data_dir'] . '/scratch/' . $this->runId;
    }

    public function runId(): string
    {
        return $this->runId;
    }

    private function say(string $s): void
    {
        $this->out[] = $s;
        fwrite(STDOUT, $s . "\n");
    }

    /** Scratch is deleted at exit on every path (normal, exception, SIGINT/SIGTERM/SIGHUP). */
    private function openScratch(): void
    {
        Fs::ensureDir($this->scratch);
        $dir = $this->scratch;
        register_shutdown_function(static fn() => Fs::rmTree($dir));
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            foreach ([SIGINT, SIGTERM, SIGHUP] as $sig) {
                pcntl_signal($sig, static function () use ($dir) {
                    Fs::rmTree($dir);
                    exit(130);
                });
            }
        }
    }

    private function fixtures(): ?string
    {
        return $this->opt['fixtures'] ?? null;
    }

    private function live(): bool
    {
        return $this->fixtures() === null && empty($this->opt['dry_run']);
    }

    /** @return array{0:string[],1:string[],2:bool} [sites, notes, partialList] */
    private function resolveSites(): array
    {
        $cfg = $this->cfg;
        $mode = $this->opt['mode'];
        $partial = false;
        if (!empty($this->opt['site'])) {
            $s = $this->opt['site'];
            if (in_array($s, $cfg['sites']['exclude'], true)) {
                throw new FlsException('site ' . $s . ' is excluded in config');
            }
            return [[$s], [], false];
        }
        if ($this->fixtures() !== null) {
            $sites = [];
            foreach (glob($this->fixtures() . '/*', GLOB_ONLYDIR) ?: [] as $d) {
                if (preg_match('/^\d{5}$/', basename($d))) {
                    $sites[] = basename($d);
                }
            }
            $inc = array_intersect($cfg['sites']['include'], $sites);
            $sites = array_values(array_diff(array_unique(array_merge($sites, $inc)), $cfg['sites']['exclude']));
            $notes = ['site list: fixtures'];
        } else {
            $src = new SiteSource($cfg);
            $sites = $src->discover($this->live());
            $notes = $src->notes;
            $partial = $src->partial;
        }
        $sites = array_values(array_filter($sites, fn($s) => Config::regionOf($cfg, $s) !== null));
        if ($mode === 'region') {
            $sites = array_values(array_filter($sites, fn($s) => Config::regionOf($cfg, $s) === $this->opt['region']));
        }
        sort($sites);
        return [$sites, $notes, $partial];
    }

    private function servers(string $site): ServerList
    {
        if ($this->fixtures() !== null) {
            return ServerList::fromFixtures($this->fixtures(), $site);
        }
        return ServerList::fromGlobal($this->cfg, $site, (string)Config::regionOf($this->cfg, $site));
    }

    private function argv(string $site, array $srv, array $args): array
    {
        if ($this->fixtures() !== null) {
            return ['/bin/bash', '-s', '--', ...$args, 'root=' . $srv['dir']];
        }
        $region = (string)Config::regionOf($this->cfg, $site);
        $jump = $this->cfg['jumps'][$region];
        $addr = $srv['addr'];
        if (!preg_match('/^[0-9A-Za-z.:-]{3,253}$/', $addr)) {
            throw new FlsException('server address rejected for ' . $site . ' ' . $srv['role']);
        }
        $ct = (int)$this->cfg['timeouts']['connect'];
        $opt = '-o BatchMode=yes -o ConnectTimeout=' . $ct . ' -o ConnectionAttempts=1 -o ForwardAgent=no';
        $inner = 'ssh ' . $opt . ' ' . $this->cfg['ssh_user'] . '@' . $addr . ' "bash -s -- ' . implode(' ', $args) . '"';
        return [$this->cfg['ssh_bin'], '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=' . $ct, '-o', 'ConnectionAttempts=1', '-o', 'ForwardAgent=no', $jump, $inner];
    }

    private function pool(): Pool
    {
        $stagger = $this->fixtures() !== null ? (float)($this->opt['stagger'] ?? 0.0) : (float)$this->cfg['stagger_s'];
        return new Pool((int)$this->cfg['lane_cap'], $stagger, (float)$this->cfg['timeouts']['total']);
    }

    private function env(): ?array
    {
        if ($this->fixtures() === null) {
            return null;
        }
        return ['TZ' => 'Asia/Seoul', 'PATH' => '/usr/bin:/bin', 'LC_ALL' => 'C'];
    }

    private function guardLive(bool $trace): void
    {
        if ($this->live() && empty($this->cfg['live']['enabled'])) {
            throw new FlsException('live SSH runs are disabled (config live.enabled=false). They need Dio\'s explicit OK. Use --dry-run or --fixtures.', 7);
        }
        if ($trace && $this->live() && empty($this->opt['per_run_ok'])) {
            throw new FlsException('a live trace needs a per-run OK: pass --per-run-ok only after Dio approves this trace.', 7);
        }
    }

    // ------------------------------------------------------------------ scan

    public function scan(): int
    {
        $this->guardLive(false);
        $this->openScratch();
        $cfg = $this->cfg;
        $state = $cfg['data_dir'] . '/state';
        [$sites, $notes, $listPartial] = $this->resolveSites();
        $payload = Payload::load($cfg['tool_dir'], 'scan-v1.sh');
        $phash = substr(hash('sha256', $payload), 0, 12);

        if ($this->fixtures() === null && !empty($this->opt['dry_run'])) {
            return $this->dryRunPlan($sites, $notes, $phash);
        }

        $jobs = [];
        $meta = [];
        $failures = [];
        $serverCount = 0;
        $cps = [];
        $hist = [];
        foreach ($sites as $site) {
            $sl = $this->servers($site);
            if ($sl->problem !== null && !$sl->servers) {
                $failures[] = ['site' => $site, 'role' => '-', 'status' => $sl->problem];
                continue;
            }
            if ($sl->problem !== null && $this->fixtures() === null) {
                $failures[] = ['site' => $site, 'role' => '-', 'status' => $sl->problem];
                continue;
            }
            $cps[$site] = Checkpoints::load($state, $site);
            $hist[$site] = GroupHistory::load($state, $site);
            $region = (string)Config::regionOf($cfg, $site);
            foreach ($sl->servers as $role => $srv) {
                $args = [['role', $srv['class']], ['since', (string)($this->now - (int)$cfg['first_run_hours'] * 3600)], ['max', (string)(int)$cfg['max_bytes_per_file']]];
                $args = array_merge($args, Checkpoints::args($cps[$site], $role));
                $rendered = Payload::args('scan-v1.sh', $args, $this->fixtures() !== null);
                $id = $site . '/' . $role;
                $jobs[] = ['id' => $id, 'lane' => Config::laneOf($cfg, $region), 'argv' => $this->argv($site, $srv, $rendered), 'stdin' => $payload, 'env' => $this->env()];
                $meta[$id] = ['site' => $site, 'role' => $role, 'class' => $srv['class']];
                $serverCount++;
            }
            unset($sl);
        }

        $pool = $this->pool();
        $results = $pool->run($jobs);
        foreach ($pool->breaker as $lane => $_) {
            $notes[] = 'circuit breaker tripped on lane ' . $lane . ' (connection reset by peer): lane paused, queued sessions skipped, no retries. Ask Dio before the next run.';
        }

        $flags = [];
        $observations = [];
        $info = [];
        $baselineSites = [];
        $baselineGroups = 0;
        $groupTable = [];
        $kh = KnownHarmless::load($cfg);
        $bySite = [];
        foreach ($results as $id => $r) {
            $bySite[$meta[$id]['site']][$id] = $r;
        }
        ksort($bySite);
        foreach ($bySite as $site => $rs) {
            $site = (string)$site;
            $observed = [];
            $roleHours = [];
            $appState = [];
            foreach ($rs as $id => $r) {
                $m = $meta[$id];
                $role = $m['role'];
                if ($r['status'] !== 'ok') {
                    $failures[] = ['site' => $site, 'role' => $role, 'status' => $r['status']];
                    continue;
                }
                $t = Tsv::parse($r['stdout']);
                if ($t->error !== null || !$t->complete) {
                    $failures[] = ['site' => $site, 'role' => $role, 'status' => $t->error ?? 'incomplete-output'];
                    continue;
                }
                if ($t->tripwire > 0) {
                    $failures[] = ['site' => $site, 'role' => $role, 'status' => 'redaction-tripwire (' . $t->tripwire . ' row(s) dropped: ' . implode(',', array_keys($t->tripClasses)) . ')'];
                }
                if ($t->header['offset'] !== '+0900') {
                    $notes[] = $site . ' ' . $role . ' server UTC offset ' . $t->header['offset'] . ' (expected +0900 KST)';
                }
                $last = GroupHistory::lastRunEpoch($hist[$site], $role);
                $hours = $last === null ? (float)$cfg['first_run_hours'] : max(1.0, min(192.0, ($this->now - $last) / 3600));
                $roleHours[$role] = round($hours, 3);
                foreach ($t->files as $label => $f) {
                    if (!$f['readable']) {
                        $failures[] = ['site' => $site, 'role' => $role, 'status' => $label . ' ' . ($f['flags'][0] ?? 'unreadable')];
                        continue;
                    }
                    foreach ($f['flags'] as $fl) {
                        if (str_starts_with($fl, 'capped:')) {
                            $notes[] = sprintf('%s %s %s capped: newest %d MB read, %.1f MB skipped', $site, $role, $label, (int)($cfg['max_bytes_per_file'] / 1048576), ((int)substr($fl, 7)) / 1048576);
                        } elseif ($fl === 'gap') {
                            $notes[] = "$site $role $label rotated past the checkpoint (gap): read what exists, bounded to the last 24 h";
                        } elseif ($fl === 'truncated') {
                            $notes[] = "$site $role $label was truncated: read from the start";
                        }
                    }
                    if (in_array('hole', $f['flags'], true)) {
                        $failures[] = ['site' => $site, 'role' => $role, 'status' => $label . ' rotation-hole'];
                    }
                }
                if (isset($t->files['app.log']) && $t->files['app.log']['readable']) {
                    $appState[$role] = $t->files['app.log'] + ['offset_tz' => $t->header['offset']];
                }
                $agg = [];
                foreach ($t->groups as $g) {
                    $k = Diff::key($g['level'], $g['category'], $g['template']);
                    $fe = Tz::serverTsToEpoch($g['first'], $t->header['offset']);
                    $le = Tz::serverTsToEpoch($g['last'], $t->header['offset']);
                    if (!isset($agg[$k])) {
                        $agg[$k] = ['role' => $role, 'class' => $m['class'], 'key' => $k, 'level' => $g['level'], 'category' => $g['category'], 'template' => $g['template'], 'count' => 0, 'hours' => $hours, 'first_epoch' => $fe, 'last_epoch' => $le];
                    }
                    $agg[$k]['count'] += $g['count'];
                    $agg[$k]['first_epoch'] = min($agg[$k]['first_epoch'] ?? PHP_INT_MAX, $fe ?? PHP_INT_MAX);
                    $agg[$k]['last_epoch'] = max($agg[$k]['last_epoch'] ?? 0, $le ?? 0);
                }
                foreach ($agg as $a) {
                    $observed[] = $a;
                }
                if (empty($this->opt['dry_run'])) {
                    $cps[$site] = Checkpoints::advance($cps[$site], $role, $t, $this->now);
                }
            }
            // stale / quiet checks on app.log
            $svc = array_filter($appState, fn($r) => str_starts_with((string)$r, 'service'), ARRAY_FILTER_USE_KEY);
            $active = array_keys(array_filter($svc, fn($f) => $f['entries'] > 0));
            foreach ($appState as $role => $f) {
                $lastE = $f['last_ts'] !== '-' ? Tz::serverTsToEpoch($f['last_ts'], $f['offset_tz']) : null;
                if ($lastE === null) {
                    $prev = $cps[$site][$role]['app.log']['last_ts'] ?? null;
                    $lastE = $prev ?: null;
                }
                $since = $lastE ? Tz::manila($lastE, 'H:i') : 'unknown';
                if ($f['entries'] === 0) {
                    if (isset($svc[$role]) && $active) {
                        $observations[] = sprintf('%s %s possibly out of rotation (quiet since %s; %s active)', $site, $role, $since, implode(', ', $active));
                    } else {
                        $info[] = "$site $role app.log quiet (info only: these logs hold only warnings and errors)";
                    }
                } elseif ($f['entries'] >= 20 && $lastE !== null && $lastE < $this->now - 3 * 3600 && ($roleHours[$role] ?? 0) >= 6) {
                    $observations[] = sprintf('%s %s app.log stopped at %s after steady activity', $site, $role, Tz::manila($lastE, 'H:i'));
                }
            }
            $ev = Diff::evaluate($site, $hist[$site], $observed, $this->now, $cfg, $kh);
            if ($ev['baseline'] && $roleHours) {
                $baselineSites[] = $site;
                $baselineGroups += count($observed);
            }
            foreach ($ev['flags'] as $f) {
                $flags[] = $f;
            }
            foreach ($observed as $o) {
                $groupTable[] = ['site' => $site] + $o;
            }
            if (empty($this->opt['dry_run'])) {
                if ($roleHours) {
                    $hist[$site] = GroupHistory::record($hist[$site], $this->now, $roleHours, $observed, (int)$cfg['diff']['history_days']);
                    GroupHistory::save($state, $site, $hist[$site]);
                }
                Checkpoints::save($state, $site, $cps[$site]);
            }
        }

        if ($listPartial) {
            $failures[] = ['site' => '-', 'role' => '-', 'status' => 'site list partial'];
        }
        $sourceProblem = $listPartial || (bool)array_filter($notes, fn($n) => str_starts_with($n, 'site list: global CLI') && str_contains($n, 'include list'));
        $run = [
            'run_id' => $this->runId, 'mode' => $this->opt['mode'], 'started' => $this->now, 'servers' => $serverCount,
            'flags' => $flags, 'failures' => $failures, 'observations' => $observations, 'notes' => array_values(array_unique($notes)),
            'baseline_sites' => $baselineSites, 'baseline_groups' => $baselineGroups,
            'payload_versions' => ['scan-v1.sh' => $phash],
        ];
        $message = $flags || $failures || $baselineSites || $sourceProblem;
        $digest = Digest::render($run);
        if ($message && !empty($cfg['model']['enabled'])) {
            [$run['summary'], $run['summary_status']] = Summary::run($cfg, $digest);
            $digest = Digest::render($run);
        } else {
            $run['summary_status'] = 'disabled';
        }
        $leak = Redact::tripwire($digest);
        if ($leak !== null) {
            // never ship a digest that still matches a redaction class
            $digest = "Fleet scan " . Tz::manila($this->now, 'd M H:i') . " — digest withheld: redaction tripwire ($leak). See the local report.\n";
            $message = true;
        }

        $deliveryStatus = 'none (quiet)';
        $quietLine = sprintf('Fleet scan %s — %d servers scanned, quiet (no new, spiking or new fatal groups; no failures).', Tz::manila($this->now, 'd M H:i'), $serverCount);
        if ($this->opt['mode'] === 'daily') {
            if ($message) {
                $this->say(rtrim($digest));
                $deliveryStatus = empty($this->opt['dry_run']) ? Delivery::queue($cfg, $this->runId, $digest, $this->live()) : 'dry-run (not queued)';
            } else {
                $this->say($quietLine);
            }
        } else {
            $this->say(rtrim($message ? $digest : $quietLine . "\n" . implode("\n", array_map(fn($l) => '— ' . $l, Digest::FOOTER))));
            $this->say('servers:');
            foreach ($results as $id => $r) {
                $this->say(sprintf('  %-16s %s', $id, $r['status']));
            }
            $this->say($this->groupTableText($groupTable));
        }

        $webhookStatus = $this->webhook($run, $message);
        $report = $this->report($run, $digest, $message, $groupTable, $info, $results, $deliveryStatus, $webhookStatus);
        Fs::writeSecure($cfg['data_dir'] . '/reports/' . $this->runId . '.txt', $report);
        if (empty($this->opt['dry_run'])) {
            Fs::writeJson($state . '/last-run.json', [
                'run_id' => $this->runId, 'mode' => $this->opt['mode'], 'started_manila' => Tz::manila($this->now, 'Y-m-d H:i:s'),
                'finished_manila' => Tz::manila(time(), 'Y-m-d H:i:s'), 'fixtures' => $this->fixtures() !== null,
                'servers' => $serverCount, 'flagged' => count($flags), 'failures' => count($failures),
                'message' => $message, 'delivery' => $deliveryStatus, 'webhook' => $webhookStatus,
                'summary' => $run['summary_status'], 'payload' => $run['payload_versions'], 'site_source' => $notes[0] ?? '',
            ]);
        }
        $this->say('report: reports/' . $this->runId . '.txt');
        return $failures ? 5 : 0;
    }

    private function webhook(array $run, bool $changed): string
    {
        $always = !empty($this->opt['webhook_always']);
        $dry = !empty($this->opt['dry_run']) || !empty($this->opt['webhook_dry_run']);
        if (!$changed && !$always) {
            return 'not sent (quiet day)';
        }
        $wh = Webhook::fromEnvFile($this->cfg['webhook_env']);
        $payload = Webhook::payload($run);
        if ($dry) {
            $this->say('webhook dry-run payload (not sent' . ($wh->enabled() ? '' : '; ' . $wh->disabledReason) . '):');
            $this->say(json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            return 'dry-run (printed, not sent)';
        }
        if (!$wh->enabled()) {
            return 'webhook disabled: ' . $wh->disabledReason;
        }
        if ($this->fixtures() !== null && !$wh->isLoopback()) {
            return 'webhook not sent: fixtures mode only posts to a loopback URL';
        }
        $st = $wh->mask($wh->post($payload));
        $this->say($st);
        return $st;
    }

    private function groupTableText(array $rows): string
    {
        if (!$rows) {
            return 'groups: none';
        }
        usort($rows, fn($a, $b) => [$a['site'], $a['role'], -$a['count']] <=> [$b['site'], $b['role'], -$b['count']]);
        $l = ['groups (redacted templates):'];
        foreach ($rows as $r) {
            $l[] = sprintf('  %s %-8s %-7s %5d  %s "%s"', $r['site'], $r['role'], $r['level'], $r['count'], $r['category'], Digest::short($r['template'], 110));
        }
        return implode("\n", $l);
    }

    private function report(array $run, string $digest, bool $message, array $groups, array $info, array $results, string $delivery, string $webhook): string
    {
        $l = ['# fleet-log-scan run ' . $this->runId, 'mode: ' . $this->opt['mode'] . ($this->fixtures() !== null ? ' (fixtures, no SSH)' : ''), 'started: ' . Tz::manila($this->now, 'Y-m-d H:i:s') . ' Asia/Manila', ''];
        $l[] = $message ? "## Digest (message)\n" . rtrim($digest) : "## Quiet day: no digest message, no webhook";
        $l[] = '';
        $l[] = '## Servers';
        foreach ($results as $id => $r) {
            $l[] = sprintf('  %-16s %-16s %.1fs', $id, $r['status'], $r['duration']);
        }
        $l[] = '';
        $l[] = '## Flags, failures, observations and notes';
        foreach ($run['flags'] as $f) {
            $l[] = sprintf('  %s %s %s %s %s "%s" count %d', $f['site'], $f['role'], $f['flag'], $f['level'], $f['category'], Digest::short($f['template'], 110), $f['count']);
        }
        foreach ($run['failures'] as $f) {
            $l[] = sprintf('  %s %s FAILED %s', $f['site'], $f['role'], $f['status']);
        }
        foreach (array_merge($run['observations'], $run['notes'], $info) as $i) {
            $l[] = '  ' . $i;
        }
        $l[] = '';
        $l[] = $this->groupTableText($groups);
        $l[] = '';
        $l[] = 'delivery (OpenClaw message to Dio): ' . $delivery;
        $l[] = 'webhook: ' . $webhook;
        $l[] = 'summary: ' . ($run['summary_status'] ?? 'disabled');
        return implode("\n", $l) . "\n";
    }

    private function dryRunPlan(array $sites, array $notes, string $phash): int
    {
        $this->say('DRY RUN — no connections are made.');
        foreach ($notes as $n) {
            $this->say('note: ' . $n);
        }
        $this->say('payload scan-v1.sh sha256 ' . $phash . '… (hash + lint OK)');
        $lanes = [];
        foreach ($sites as $s) {
            $r = (string)Config::regionOf($this->cfg, $s);
            $lanes[Config::laneOf($this->cfg, $r)][] = $s . '(' . $r . ')';
        }
        foreach ($lanes as $lane => $ss) {
            $this->say(sprintf('lane %s: cap %d, stagger %.1fs, timeouts connect %ds total %ds: %s', $lane, $this->cfg['lane_cap'], $this->cfg['stagger_s'], $this->cfg['timeouts']['connect'], $this->cfg['timeouts']['total'], implode(' ', $ss)));
        }
        if (!$sites) {
            $this->say('no sites resolved (fill sites.include in config.php, or run live discovery after Dio\'s OK)');
        }
        $this->say('per server (servers resolved from global `server list` at run time; addresses never shown):');
        $ct = (int)$this->cfg['timeouts']['connect'];
        $this->say("  ssh -o BatchMode=yes -o ConnectTimeout={$ct} -o ConnectionAttempts=1 -o ForwardAgent=no rti-jump-<region> 'ssh -o BatchMode=yes -o ConnectTimeout={$ct} -o ConnectionAttempts=1 -o ForwardAgent=no wwkker@<server> \"bash -s -- role=<class> since=<epoch> max=<bytes> ck=<label:inode:offset:lastts>…\"' < payload/scan-v1.sh");
        if (!empty($this->opt['webhook_dry_run']) || !empty($this->opt['webhook_always'])) {
            $wh = Webhook::fromEnvFile($this->cfg['webhook_env']);
            $this->say('webhook: ' . ($wh->enabled() ? 'configured (URL hidden); dry-run prints the payload after a scan' : 'disabled: ' . $wh->disabledReason));
        }
        return 0;
    }

    // ------------------------------------------------------------------ trace

    public function trace(): int
    {
        $cfg = $this->cfg;
        $rid = (string)$this->opt['request_id'];
        if (!preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/', $rid)) {
            throw new FlsException('request id must be a 36-char uuid', 2);
        }
        $site = (string)($this->opt['site'] ?? '');
        if (!preg_match('/^\d{5}$/', $site)) {
            throw new FlsException('--site <id> is required for a trace (no fleet-wide sweep)', 2);
        }
        if (Config::regionOf($cfg, $site) === null) {
            throw new FlsException('unknown region prefix for site ' . $site, 2);
        }
        $to = $this->opt['to'] ?? $this->now;
        $from = $this->opt['from'] ?? ($to - (int)$cfg['trace']['default_days'] * 86400);
        if ($from >= $to) {
            throw new FlsException('--from must be before --to', 2);
        }
        $this->guardLive(true);
        $this->openScratch();
        $payload = Payload::load($cfg['tool_dir'], 'trace-v1.sh');
        if ($this->fixtures() === null && !empty($this->opt['dry_run'])) {
            $this->say('DRY RUN — trace not executed. Would search site ' . $site . ' (all roles) for the request id between ' . Tz::manila($from) . ' and ' . Tz::manila($to) . ' Asia/Manila, with payload trace-v1.sh.');
            return 0;
        }
        $sl = $this->servers($site);
        if (!$sl->servers) {
            $this->say("trace $site: server list unreadable");
            return 5;
        }
        $jobs = [];
        $region = (string)Config::regionOf($cfg, $site);
        foreach ($sl->servers as $role => $srv) {
            $args = Payload::args('trace-v1.sh', [['id', strtolower($rid)], ['from', (string)$from], ['to', (string)$to]], $this->fixtures() !== null);
            $jobs[] = ['id' => $role, 'lane' => Config::laneOf($cfg, $region), 'argv' => $this->argv($site, $srv, $args), 'stdin' => $payload, 'env' => $this->env()];
        }
        unset($sl);
        $results = $this->pool()->run($jobs);
        ksort($results);
        $rows = [];
        $earliest = [];
        $fail = [];
        $hits = [];
        foreach ($results as $role => $r) {
            if ($r['status'] !== 'ok') {
                $fail[] = "$role: " . $r['status'];
                continue;
            }
            $t = Tsv::parse($r['stdout'], [strtolower($rid)]);
            if ($t->error !== null || !$t->complete) {
                $fail[] = "$role: " . ($t->error ?? 'incomplete-output');
                continue;
            }
            if ($t->tripwire) {
                $fail[] = "$role: redaction-tripwire ({$t->tripwire} entr(ies) withheld)";
            }
            $off = $t->header['offset'];
            $min = null;
            foreach ($t->ranges as $rg) {
                $e = $rg['earliest'] !== '-' ? Tz::serverTsToEpoch($rg['earliest'], $off) : null;
                if ($e !== null) {
                    $min = $min === null ? $e : min($min, $e);
                }
            }
            $earliest[$role] = $min;
            $hits[$role] = array_sum(array_column($t->ranges, 'hits'));
            foreach ($t->matches as $m) {
                $rows[] = ['role' => $role, 'epoch' => Tz::serverTsToEpoch($m['ts'], $off) ?? 0] + $m;
            }
        }
        usort($rows, fn($a, $b) => [$a['role'], $a['epoch']] <=> [$b['role'], $b['epoch']]);
        $this->say(sprintf('Trace %s on site %s, %s to %s Asia/Manila (shown here only; not stored)', $rid, $site, Tz::manila($from), Tz::manila($to)));
        $bytes = 0;
        $shown = 0;
        $total = max(count($rows), array_sum($hits));
        foreach ($rows as $r) {
            $line = sprintf('  %s %s  %s %s  %s', $r['role'], Tz::manila($r['epoch'], 'Y-m-d H:i:s'), $r['level'], $r['category'], self::traceWording($r));
            $bytes += strlen($line);
            if ($shown >= (int)$cfg['trace']['max_entries'] || $bytes > (int)$cfg['trace']['max_bytes']) {
                break;
            }
            $this->say($line);
            $shown++;
        }
        if ($total > $shown) {
            $this->say(sprintf('  … %d more entr(ies) not shown (cap %d entries / %d KB)', $total - $shown, $cfg['trace']['max_entries'], $cfg['trace']['max_bytes'] / 1024));
        }
        if (!$rows) {
            $this->say('  Not found in readable logs. This codebase does not log a response status for successful requests.');
            $this->say('  A miss can mean: the request succeeded; it was suppressed by the 5-minute dedup; it hit a non-PlayTime route; the id came from elsewhere (client, proxy, provider); or the log already rotated out.');
        }
        foreach ($earliest as $role => $e) {
            $this->say(sprintf('  %s earliest readable entry: %s', $role, $e ? Tz::manila($e, 'Y-m-d H:i') : 'none'));
        }
        foreach ($fail as $f) {
            $this->say('  FAILED ' . $f);
        }
        if (empty($this->opt['dry_run'])) {
            Fs::writeJson($cfg['data_dir'] . '/state/last-run.json', [
                'run_id' => $this->runId, 'mode' => 'trace', 'site' => $site, 'fixtures' => $this->fixtures() !== null,
                'started_manila' => Tz::manila($this->now, 'Y-m-d H:i:s'), 'hits' => $hits, 'failures' => count($fail),
            ]);
        }
        return $fail ? 5 : 0;
    }

    public static function traceWording(array $r): string
    {
        $kv = $r['kv'];
        $msg = $kv['message'] ?? $r['head'];
        $sup = isset($kv['suppressed_repeats']) && (int)$kv['suppressed_repeats'] > 0 ? ' (' . (int)$kv['suppressed_repeats'] . ' repeats suppressed by dedup)' : '';
        if (stripos($msg, 'Play time API action failed') !== false) {
            return 'Failed: 500 (action threw ' . ($kv['exception'] ?? 'unknown exception') . ')' . (isset($kv['route']) ? ' route ' . $kv['route'] : '') . $sup;
        }
        if (stripos($msg, 'invalid UTF-8') !== false) {
            return 'Failed: 500 (wallet response contains invalid UTF-8)' . $sup;
        }
        if (isset($kv['http_status'])) {
            return 'Logged HTTP ' . $kv['http_status'] . (isset($kv['classification']) ? ' (' . $kv['classification'] . ')' : '') . (isset($kv['route']) ? ' route ' . $kv['route'] : '') . $sup;
        }
        if (isset($kv['via'])) {
            return 'Request context dump (' . ($kv['method'] ?? '?') . ' ' . ($kv['path'] ?? '?') . '); no status logged';
        }
        return 'Logged ' . $r['level'] . ': ' . Digest::short($msg, 120) . $sup;
    }
}
