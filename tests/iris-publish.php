<?php
declare(strict_types=1);

// Standalone: no network, no fixtures logs. Prints only "iris-publish tests: N passed".
define('TOOL', dirname(__DIR__));
foreach (['Util', 'Redact', 'Config', 'Payload', 'Sites', 'Pool', 'Tsv', 'State', 'Diff', 'Outputs', 'IrisPublish', 'Runner'] as $f) {
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

if ($fail) {
    exit(1);
}
echo "iris-publish tests: $pass passed\n";
