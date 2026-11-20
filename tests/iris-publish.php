<?php
declare(strict_types=1);

// Standalone: no network, no fixtures logs. Prints only "iris-publish tests: N passed".
define('TOOL', dirname(__DIR__));
foreach (['Util', 'Redact', 'Config', 'Payload', 'Sites', 'Pool', 'Tsv', 'State', 'Diff', 'Outputs', 'IrisPatterns', 'IrisPublish', 'Runner'] as $f) {
    require_once TOOL . '/lib/' . $f . '.php';
}

use Fls\IrisPublish;

$pass = 0;
$fail = 0;
$t = static function (bool $ok, string $name) use (&$pass, &$fail): void {
    if ($ok) {
        $pass++;
    } else {
        $fail++;
        fwrite(STDERR, "FAIL: $name\n");
    }
};

$sg = [
    'schema_version' => '1.0',
    'report_type' => 'fleet_log_scan',
    'job' => ['job_id' => 'job1', 'run_id' => '20261119T101500-abc123', 'requested_by' => 'someone@example.test'],
    'scope' => ['region' => 'sg', 'jump_alias' => 'jumpx', 'mode' => 'read_only', 'sites' => ['NNNNN'],
        'window' => ['type' => 'daily', 'hours' => 24, 'end' => '2026-11-19T02:15:00Z']],
    'timing' => ['started_at' => '2026-11-19T02:15:00Z', 'finished_at' => '2026-11-19T02:16:00Z', 'duration_seconds' => 60],
    'result' => ['status' => 'ok', 'exit_code' => 0, 'roles_total' => 1, 'roles_ok' => 1, 'roles_failed' => 0],
    'totals' => ['errors' => 1, 'warnings' => 0, 'fatals' => 0, 'http_500_bursts' => 0],
    'sites' => [['site_id' => 'NNNNN', 'roles_total' => 1, 'roles_ok' => 1, 'errors' => 1, 'warnings' => 0,
        'roles' => [['role' => 'admin', 'status' => 'ok', 'duration_seconds' => 1.0, 'checkpoint_saved' => true,
            'byte_cap_hits' => [['file' => '/var/log/app/x.log', 'skipped_mb' => 2]]]]]],
    'top_signatures' => [
        ['rank' => 1, 'count' => 3, 'level' => 'error', 'severity' => 'high', 'locations' => ['NNNNN/admin'], 'signature' => '/site/index failed'],
        ['rank' => 2, 'count' => 1, 'level' => 'error', 'severity' => 'low', 'locations' => ['NNNNN/admin'], 'signature' => 'leak from 198.51.100.23 seen'],
    ],
    'urgent' => [['id' => 'u1', 'severity' => 'high', 'title' => 'Something urgent', 'sites' => ['NNNNN'], 'roles' => ['admin']]],
    'coverage_gaps' => [['type' => 'timeout', 'fix' => 'raise the timeout']],
    'config' => ['connect_timeout_seconds' => 5, 'total_timeout_seconds' => 60, 'byte_cap_mb_per_file' => 50, 'first_run_hours' => 24],
    'safety' => ['live_enabled_after_run' => false, 'state_disabled_present' => false, 'webhook_env_present' => false,
        'launch_agent_present' => false, 'summary_model_used' => false, 'delivery' => 'none', 'ipv4_in_outputs' => 0,
        'secrets_in_outputs' => 0, 'server_writes' => false, 'sudo_used' => false],
    'artifacts' => ['report_md' => 'reports/report.md', 'tool_report' => '~/tool/report.txt'],
];

$a = IrisPublish::augment($sg);
$dropped = IrisPublish::dropped();
$t(($a['run_type'] ?? '') === 'fleet_log_scan', 'run_type added');
$t(!isset($a['scope']['jump_alias']), 'jump_alias removed');
$t($a['artifacts']['report_md'] === 'report.md', 'report_md basename');
$t($a['artifacts']['tool_report'] === 'report.txt', 'tool_report basename');
$t($a['sites'][0]['roles'][0]['byte_cap_hits'][0]['file'] === 'x.log', 'byte cap file basename');
$t(str_starts_with($a['top_signatures'][0]['signature'], 'error: /'), 'signature prefixed');
$t($a['job']['requested_by'] === 'scheduler', 'requested_by normalized');
$t(count($a['top_signatures']) === 1 && $dropped === 1, 'tripwire drop counted');
$t(!str_contains(json_encode($a), '198.51.100'), 'matched text absent');
$t(($a['suggested_fixes'][0]['source'] ?? '') === 'rule' && count($a['suggested_fixes']) === 2, 'rule fixes built');
$t(preg_match('/^[0-9a-f]{64}$/', $a['payload_hash']) === 1, 'hash is 64 hex');

$sg2 = array_reverse($sg, true);
$sg2["scope"] = array_reverse($sg['scope'], true);
$t(IrisPublish::augment($sg2)['payload_hash'] === $a['payload_hash'], 'hash stable across key order');
$t(IrisPublish::hash($a) === $a['payload_hash'], 'hash excludes payload_hash');

$keep = $sg;
$keep['suggested_fixes'] = [];
$t(IrisPublish::augment($keep)['suggested_fixes'] === [], 'existing suggested_fixes kept');
$vc = $sg;
$vc['report_type'] = 'version_check';
$t(IrisPublish::augment($vc)['run_type'] === 'version_check', 'run_type follows report_type');

$run = ['run_id' => '20261119T101500-abc123', 'mode' => 'daily', 'started' => 1795140900, 'servers' => 4,
    'flags' => [], 'failures' => [], 'observations' => [], 'notes' => [], 'baseline_sites' => [], 'baseline_groups' => [],
    'payload_versions' => [], 'summary_status' => 'disabled'];
$q = IrisPublish::fromRun($run, [], 1795141000);
$t(($q['schema_version'] ?? '') === '1.0', 'fromRun schema_version');
$t(!array_key_exists('schema', $q), 'no webhook.v1 schema key');
$t($q['scope']['region'] === 'sg' && $q['scope']['mode'] === 'read_only' && $q['scope']['sites'] === [], 'fromRun scope');
$t($q['job']['run_id'] === $run['run_id'] && $q['suggested_fixes'] === [], 'fromRun run_id kept, no fixes');
$t(IrisPublish::fromRun($run, ['fixtures' => 'x'], 1795141000)['scope']['mode'] === 'fixtures', 'fixtures mode');

$run['flags'] = [['site' => '10001', 'role' => 'admin', 'flag' => 'new', 'level' => 'error', 'category' => 'c', 'template' => 'boom', 'count' => 2, 'rate' => 1.0, 'usual' => null, 'factor' => null]];
$run['failures'] = [['site' => '-', 'role' => '-', 'status' => 'site list partial']];
$f = IrisPublish::fromRun($run, [], 1795141000);
$t($f['scope']['region'] === 'jp' && $f['scope']['sites'] === ['10001'] && $f['result']['status'] === 'partial', 'fromRun flags/failures');

$t(IrisPublish::postsOnQuietDay(false) === false && IrisPublish::postsOnQuietDay(true) === true, 'quiet-day default');
$help = (string)shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(TOOL . '/fleet-log-scan.php') . ' --help 2>&1');
$t(str_contains($help, '--iris-publish'), 'help mentions --iris-publish');

$epoch = (new DateTimeImmutable('2026-11-19T05:02:00+08:00'))->getTimestamp();
$structured = [
    'run_id' => 'not-a-run-id',
    'mode' => 'daily',
    'started' => 1763514120,
    'servers' => 4,
    'executor' => 'cursor',
    'summary_status' => 'summary ok',
    'connect_timeout' => 15,
    'total_timeout' => 120,
    'window_hours' => 24,
    'flags' => [
        ['site' => '11050', 'role' => 'admin', 'flag' => 'new-fatal', 'level' => 'fatal', 'category' => 'c', 'template' => 'Required server command failed: lock', 'count' => 4, 'rate' => 1.0, 'usual' => null, 'factor' => null],
        ['site' => '11080', 'role' => 'db', 'flag' => 'new', 'level' => 'error', 'category' => 'c', 'template' => 'Connection refused', 'count' => 9, 'rate' => 1.0, 'usual' => null, 'factor' => null],
        ['site' => '11090', 'role' => 'admin', 'flag' => 'new', 'level' => 'error', 'category' => 'c', 'template' => 'Connection refused', 'count' => 2, 'rate' => 1.0, 'usual' => null, 'factor' => null],
    ],
    'failures' => [
        ['site' => '11050', 'role' => 'db', 'status' => 'timeout'],
        ['site' => '11100', 'role' => 'db', 'status' => 'timeout'],
    ],
    'quiet' => [
        ['site' => '11080', 'role' => 'admin', 'epoch' => $epoch],
        ['site' => '11120', 'role' => 'db', 'epoch' => null],
    ],
];
$s = IrisPublish::fromRun($structured, [], 1763514300);
$t(preg_match('/^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/', $s['job']['run_id']) === 1, 'invalid run id rewritten with Z');
$t($s['job']['executor'] === 'cursor' && !isset($s['job']['model']), 'executor set, model absent');
$t($s['safety']['summary_model_used'] === false, 'digest summary ok does not mark the model');
$t($s['timing']['timezone_note'] === 'Human clock is Asia/Manila.', 'timezone note stays Manila');
$t($s['scope']['window']['hours'] === 24 && $s['config']['connect_timeout_seconds'] === 15 && $s['config']['total_timeout_seconds'] === 120, 'window and timeouts filled');
$gap = $s['coverage_gaps'][0];
$t($gap['type'] === 'timeout' && $gap['note'] === 'Same problem as 30000/db.' && $gap['roles'] === ['11050/db', '11100/db'], 'db timeout gap uses the pattern');
$db = null;
foreach ($s['sites'] as $site) {
    foreach ($site['roles'] as $role) {
        if ($site['site_id'] === '11050' && $role['role'] === 'db') {
            $db = $role;
        }
    }
}
$t($db !== null && $db['status'] === 'timeout' && ($db['error']['type'] ?? '') === 'timeout' && ($db['error']['limit_seconds'] ?? 0) === 120, 'timeout role carries the limit');
$adminClock = null;
$unknownClock = null;
foreach ($s['sites'] as $site) {
    foreach ($site['roles'] as $role) {
        if ($site['site_id'] === '11080' && $role['role'] === 'admin') {
            $adminClock = $role['log_last_write_clock'] ?? null;
        }
        if ($site['site_id'] === '11120' && $role['role'] === 'db') {
            $unknownClock = $role['log_last_write_clock'] ?? null;
        }
    }
}
$t($adminClock === ['time' => '2026-11-19T05:02:00+08:00', 'timezone' => 'Asia/Manila', 'note' => 'stopped writing'], 'quiet clock is Manila RFC3339');
$t($unknownClock === ['note' => 'last write time unknown'], 'unknown epoch omits the time');
$t(($s['urgent'][0]['severity'] ?? '') === 'critical' && ($s['urgent'][0]['detail'] ?? '') === 'Same pattern as 30010 on VERTEX.', 'fatal pattern is the first urgent');
$refused = null;
foreach ($s['urgent'] as $u) {
    if (str_contains($u['title'], 'Connection refused')) {
        $refused = $u;
    }
}
$t($refused !== null && $refused['count'] === 11 && ($refused['breakdown']['11080']['db'] ?? 0) === 9 && ($refused['breakdown']['11090']['admin'] ?? 0) === 2, 'breakdown sums the signature');
$siteIds = array_column($s['sites'], 'site_id');
$t(!in_array('30000', $siteIds, true) && $s['suggested_fixes'] === [], 'pattern text is not a site id');

$adminTimeout = [
    'run_id' => '20261119T101500-abc123', 'mode' => 'daily', 'started' => 1795140900, 'servers' => 1,
    'flags' => [], 'failures' => [['site' => '11050', 'role' => 'admin', 'status' => 'timeout']],
];
$at = IrisPublish::fromRun($adminTimeout, [], 1795141000);
$t(($at['coverage_gaps'][0]['note'] ?? '') === 'Read timed out on 11050/admin.', 'non-db timeout names the role');

$memDir = sys_get_temp_dir() . '/fls-iris-remember-' . getmypid();
$memPath = $memDir . '/frozen.iris.json';
$frozen = IrisPublish::remember($memPath, $s);
$mutated = $s;
$mutated['schema_version'] = '9.9';
$kept = IrisPublish::remember($memPath, $mutated);
$t($frozen['payload_hash'] === $s['payload_hash'] && $kept['schema_version'] === '1.0' && $kept['payload_hash'] === $s['payload_hash'], 'remember resends the first document');
@unlink($memPath);
@rmdir($memDir);

$fixture = json_decode((string)file_get_contents(TOOL . '/tests/fixtures/iris-summary-sg.json'), true);
$t(is_array($fixture) && ($fixture['timing']['timezone_note'] ?? '') === 'Human clock is Asia/Manila.', 'shared SG fixture keeps the source clock');

if ($fail) {
    exit(1);
}
echo "iris-publish tests: $pass passed\n";
