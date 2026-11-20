<?php
declare(strict_types=1);

// Standalone: no network, no fixtures logs. Prints only "iris-publish tests: N passed".
define('TOOL', dirname(__DIR__));
foreach (['Util', 'Redact', 'Config', 'Payload', 'Sites', 'Pool', 'Tsv', 'State', 'Diff', 'Outputs', 'IrisPatterns', 'IrisPublish', 'SummaryNumberTrace', 'IrisSummaryVerifier', 'IrisSummary', 'Runner'] as $f) {
    require_once TOOL . '/lib/' . $f . '.php';
}

use Fls\IrisPublish;
use Fls\IrisSummary;
use Fls\SummaryNumberTrace;

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

$vectors = json_decode((string)file_get_contents(TOOL . '/tests/fixtures/summary-number-trace-vectors.json'), true);
$vectorOk = true;
foreach ($vectors['cases'] as $case) {
    $bad = SummaryNumberTrace::firstUntraced($case['text'], $case['doc']);
    if ($case['ok'] ? $bad !== null : $bad === null) {
        $vectorOk = false;
    }
}
$t($vectorOk, 'shared number-trace vectors');
$t(SummaryNumberTrace::displayZone(['timing' => ['timezone_note' => 'Human clock is NotA/Zone.']])->getName() === 'Asia/Dubai', 'display zone falls back to Dubai');
$t(SummaryNumberTrace::displayZone(['timing' => ['timezone_note' => 'Human clock is Asia/Manila.']])->getName() === 'Asia/Manila', 'source note still selects Manila');
$t(IrisSummary::enabled(['iris_summary' => true]) === false && IrisSummary::enabled(['iris_summary' => true, 'iris_publish' => true]) === true, 'summary flag needs publish');
$t(str_contains($help, '--iris-summary'), 'help mentions --iris-summary');
$alone = (string)shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(TOOL . '/fleet-log-scan.php') . ' --daily --iris-summary 2>&1');
$t(str_contains($alone, '--iris-summary is only allowed with --iris-publish'), 'summary flag refused without publish');

$base = IrisPublish::fromRun([
    'run_id' => '20261119T101500-abc123', 'mode' => 'daily', 'started' => 1795140900, 'servers' => 1,
    'flags' => [], 'failures' => [], 'summary_status' => 'summary ok',
], [], 1795141000);
$clean = "The SG log scan is done.\n\nWhat stands out:\n- a quiet fleet\n\nQuiet logs: none reported.\n\nMissing from this scan: there were no PHP fatals.\n\nMost urgent: none recorded.";
$seenArgv = null;
$seenCwd = null;
$calls = 0;
$runner = static function (array $argv, string $cwd) use (&$seenArgv, &$seenCwd, &$calls, $clean): array {
    $calls++;
    $seenArgv = $argv;
    $seenCwd = $cwd;
    $empty = array_diff(scandir($cwd) ?: [], ['.', '..']) === [];
    if (!$empty || !str_starts_with(basename($cwd), 'fls-iris-')) {
        return ['exit' => 1, 'stdout' => '', 'timedOut' => false];
    }
    return ['exit' => 0, 'stdout' => $clean, 'timedOut' => false];
};
$attached = IrisSummary::attach($base, ['runner' => $runner]);
$argv = $attached['argv'] ?? [];
$exact = ($argv[0] ?? '') === 'cursor-agent' && ($argv[1] ?? '') === '-p' && ($argv[2] ?? '') === '--model'
    && ($argv[3] ?? '') === 'grok-4.7-high' && ($argv[4] ?? '') === '--trust' && ($argv[5] ?? '') === '--force'
    && ($argv[6] ?? '') === '--mode' && ($argv[7] ?? '') === 'ask' && ($argv[8] ?? '') === '--output-format'
    && ($argv[9] ?? '') === 'text' && is_string($argv[10] ?? null);
$joined = implode("\n", $argv);
$t($calls === 1 && $exact && !str_contains($joined, 'yolo') && !str_contains($joined, '-fast'), 'summary argv is grok-4.7-high ask text');
$t(is_string($seenCwd) && !is_dir($seenCwd), 'summary temp dir is removed');
$t(($attached['doc']['ai_summary']['status'] ?? '') === 'ok' && ($attached['doc']['ai_summary']['model'] ?? '') === 'grok-4.7-high' && ($attached['doc']['safety']['summary_model_used'] ?? false) === true, 'verified text is attached');
$t(!str_contains((string)($argv[10] ?? ''), 'payload_hash') && str_contains((string)($argv[10] ?? ''), 'Asia/Manila'), 'prompt embeds the document without the hash');

$skipCase = static function (array $ran) use ($base): array {
    return IrisSummary::attach($base, ['runner' => static fn(array $argv, string $cwd): array => $ran]);
};
$t($skipCase(['exit' => 0, 'stdout' => '', 'timedOut' => false])['reason'] === 'empty', 'empty summary is skipped');
$t($skipCase(['exit' => 0, 'stdout' => $clean, 'timedOut' => true])['reason'] === 'timeout', 'timed out summary is skipped');
$missing = IrisSummary::attach($base, ['bin' => '/tmp/fls-no-such-cursor-agent']);
$t($missing['reason'] === 'missing-cli' && $missing['argv'] === null, 'missing CLI is skipped without a call');
$untraced = $skipCase(['exit' => 0, 'stdout' => $clean . "\n\nCounted 99999 items.", 'timedOut' => false]);
$t($untraced['reason'] === 'summary_untraced' && ($untraced['doc']['ai_summary']['text'] === null) && ($untraced['doc']['safety']['summary_model_used'] ?? true) === false, 'untraced number is skipped');
$quad = implode('.', ['203', '0', '113', '10']);
$ip = $skipCase(['exit' => 0, 'stdout' => $clean . "\n\nAddress " . $quad . " was seen.", 'timedOut' => false]);
$t($ip['reason'] === 'ipv4' && ($ip['doc']['ai_summary']['text'] === null), 'ip text is skipped');
$home = $skipCase(['exit' => 0, 'stdout' => $clean . "\n\nSee /home/scan for the note.", 'timedOut' => false]);
$t($home['reason'] === 'path', 'home path text is skipped');
$dirty = $base;
$dirty['note'] = 'seen ' . $quad;
$blocked = IrisSummary::attach($dirty, ['runner' => static function () use (&$calls) {
    $calls++;
    return ['exit' => 0, 'stdout' => '', 'timedOut' => false];
}]);
$t($blocked['reason'] === 'tripwire' && $blocked['argv'] === null, 'prompt tripwire skips the model');
$huge = $base;
$huge['note'] = str_repeat('a', 270000);
$tooBig = IrisSummary::attach($huge, ['runner' => static function () use (&$calls) {
    $calls++;
    return ['exit' => 0, 'stdout' => $clean, 'timedOut' => false];
}]);
$t($tooBig['reason'] === 'prompt-too-large' && $tooBig['argv'] === null, 'oversized prompt skips the model');

$logDir = sys_get_temp_dir() . '/fls-iris-log-' . getmypid();
mkdir($logDir, 0700);
$logged = IrisSummary::attach($base, [
    'runner' => static fn(): array => ['exit' => 0, 'stdout' => '', 'timedOut' => false],
    'log' => $logDir . '/summary.log',
]);
$t($logged['reason'] === 'empty' && trim((string)file_get_contents($logDir . '/summary.log')) === 'empty', 'skip reason stays in the local log');
@unlink($logDir . '/summary.log');
@rmdir($logDir);

$withOk = $attached['doc'];
$postDir = sys_get_temp_dir() . '/fls-iris-post-' . getmypid();
mkdir($postDir, 0700);
$posts = [];
$client = static function (array $doc) use (&$posts): array {
    $posts[] = $doc;
    if (count($posts) === 1) {
        return ['code' => 422, 'body' => json_encode(['violations' => [['pointer' => '/ai_summary/text', 'rule' => 'summary_untraced']]])];
    }
    return ['code' => 201, 'body' => ''];
};
$delivered = IrisPublish::deliver($postDir . '/one.iris.json', $withOk, $client);
$t(count($posts) === 2 && $delivered['result']['code'] === 201, 'summary 422 is posted once more');
$t(($posts[1]['ai_summary']['status'] ?? '') === 'skipped' && ($posts[1]['ai_summary']['text'] === null) && ($posts[1]['safety']['summary_model_used'] ?? true) === false, 'the retry is skipped with the flag off');
$other = [];
IrisPublish::deliver($postDir . '/two.iris.json', $withOk, static function (array $doc) use (&$other): array {
    $other[] = $doc;
    return ['code' => 422, 'body' => json_encode(['violations' => [['pointer' => '/sites/0', 'rule' => 'unknown_site']]])];
});
$t(count($other) === 1, 'a non-summary 422 is not retried');
@unlink($postDir . '/one.iris.json');
@unlink($postDir . '/two.iris.json');
@rmdir($postDir);


// ---- Iris publish cap (synthetic documents only) ----
$capDoc = static function (array $over = []): array {
    $sigs = [];
    for ($i = 0; $i <= 500; $i++) {
        $locs = $i === 0 ? ['11111/admin', 'NOSUCH/admin'] : ['11111/admin'];
        $sigs[] = ['rank' => $i + 1, 'count' => 1000 - $i, 'level' => 'warning', 'severity' => 'medium', 'locations' => $locs, 'signature' => sprintf('tmpl-%04d', $i)];
    }
    $urgent = [];
    for ($i = 0; $i < 200; $i++) {
        $urgent[] = ['id' => sprintf('u-%04d', $i), 'severity' => 'critical', 'title' => sprintf('Urgent row %04d', $i), 'count' => 1];
    }
    $urgent[] = ['id' => 'u-big', 'severity' => 'medium', 'title' => 'Big but medium', 'count' => 999];
    $doc = [
        'schema_version' => '1.0', 'report_type' => 'fleet_log_scan',
        'job' => ['job_id' => 'sg-log-scan-20261120', 'run_id' => '20261120T080000Z-abc123', 'requested_by' => 'scheduler'],
        'scope' => ['region' => 'sg', 'mode' => 'read_only', 'sites' => ['11111'],
            'window' => ['type' => 'daily', 'hours' => 24, 'end' => '2026-11-20T02:15:00Z']],
        'timing' => ['started_at' => '2026-11-20T02:15:00Z', 'finished_at' => '2026-11-20T02:16:00Z', 'duration_seconds' => 60],
        'result' => ['status' => 'ok', 'exit_code' => 0, 'roles_total' => 1, 'roles_ok' => 1, 'roles_failed' => 0, 'flagged_new_groups' => 3],
        'totals' => ['errors' => 5, 'warnings' => 7, 'fatals' => 0, 'http_500_bursts' => 0],
        'sites' => [['site_id' => '11111', 'roles_total' => 1, 'roles_ok' => 1, 'errors' => 5, 'warnings' => 7,
            'roles' => [['role' => 'admin', 'status' => 'ok', 'duration_seconds' => 3, 'checkpoint_saved' => true]]]],
        'top_signatures' => $sigs,
        'urgent' => $urgent,
        'coverage_gaps' => [],
        'config' => ['connect_timeout_seconds' => 5, 'total_timeout_seconds' => 60, 'byte_cap_mb_per_file' => 50, 'first_run_hours' => 24],
        'safety' => ['live_enabled_after_run' => false, 'state_disabled_present' => false, 'webhook_env_present' => false,
            'launch_agent_present' => false, 'summary_model_used' => false, 'delivery' => 'none', 'ipv4_in_outputs' => 0,
            'secrets_in_outputs' => 0, 'server_writes' => false, 'sudo_used' => false],
        'artifacts' => ['report_md' => null, 'tool_report' => 'scan-20261120.txt'],
        'suggested_fixes' => [],
    ];
    return $over + $doc;
};
$limit = 1048576 - 40960;
$body = static fn(array $d): int => strlen((string)json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
$dupes = static function (array $d): bool {
    $keys = array_map(fn($r) => $r['level'] . "\n" . $r['signature'], $d['top_signatures']);
    $ids = array_column($d['urgent'], 'id');
    return count($keys) !== count(array_unique($keys)) || count($ids) !== count(array_unique($ids));
};

$big = IrisPublish::augment($capDoc());
$t(count($big['top_signatures']) === 500 && array_column($big['top_signatures'], 'rank') === range(1, 500), 'cap: 500 signatures ranked 1..500');
$t($big['top_signatures'][0]['signature'] === 'tmpl-0000' && $big['top_signatures'][0]['locations'] === ['11111/admin'], 'cap: first signature kept, bad location dropped');
$t(count($big['urgent']) === 200 && array_unique(array_column($big['urgent'], 'severity')) === ['critical'] && !in_array('u-big', array_column($big['urgent'], 'id'), true), 'cap: 200 critical urgent, u-big dropped');
$t(($big['result']['groups_recorded'] ?? 0) === 501, 'cap: groups_recorded is the pre-cap count');
$note = (string)($big['result']['flagged_note'] ?? '');
$t(str_starts_with($note, 'Iris caps: kept 500 of 501 signatures, 200 of 201 urgent') && str_contains($note, 'truncated 1') && mb_strlen($note) <= 500, 'cap: flagged_note sentence');
$t($big['totals'] === ['errors' => 5, 'warnings' => 7, 'fatals' => 0, 'http_500_bursts' => 0] && $big['result']['flagged_new_groups'] === 3 && $big['result']['roles_total'] === 1, 'cap: totals unchanged');
$t($big['artifacts']['tool_report'] === null, 'cap: digit-run tool_report cleared');
$t($big['payload_hash'] === IrisPublish::hash($big) && $body($big) <= $limit, 'cap: hash matches, body fits');
$again = IrisPublish::augment($big);
$t($again['payload_hash'] === $big['payload_hash'] && $again['result']['flagged_note'] === $note, 'cap: second pass changes nothing');
$t(!$dupes($big), 'cap: no duplicate signatures or urgent ids');
$t(!isset(IrisPublish::capStats()['n']) || IrisPublish::capStats()['n']['cut'] === 0, 'cap: stats show nothing new on the second pass');

$autoload = '/Users/diorti/Documents/codes/rti/fleet-reporter/vendor/autoload.php';
$haveAutoload = is_file($autoload);
$t($haveAutoload, 'fleet-reporter autoload exists');
$valid = static function (array $d) use ($haveAutoload): bool {
    if (!$haveAutoload) {
        return false;
    }
    $obj = json_decode((string)json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    return (new \app\services\SchemaValidator())->validate($obj) === [] && (new \app\support\Redactor())->scan($obj) === []
        && \app\support\Canonical::hash($obj) === $d['payload_hash'];
};
if ($haveAutoload) {
    require_once $autoload;
}
$t($valid($big), 'cap: schema, redactor and canonical hash agree');

$noFix = $capDoc();
unset($noFix['suggested_fixes']);
$nf = IrisPublish::augment($noFix);
$t(count($nf['suggested_fixes']) === 200 && $valid($nf), 'cap: 201 urgent rows give exactly 200 fixes');
$t(!in_array('u-big', array_column($nf['suggested_fixes'], 'issue_ref'), true) && str_contains($nf['result']['flagged_note'], 'kept 200 of 201 fixes'), 'cap: fix for the dropped urgent row is the one left out');

$noId = $sg;
$noId['urgent'] = [['severity' => 'critical', 'title' => 'No id row', 'count' => 5, 'sites' => ['NNNNN'], 'roles' => ['admin']]];
$ni = IrisPublish::augment($noId);
$niId = $ni['urgent'][0]['id'] ?? '';
$ni2 = IrisPublish::augment($ni);
$t(count($ni['urgent']) === 1 && preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $niId) === 1 && !preg_match('/\d/', $niId) && ($ni2['urgent'][0]['id'] ?? null) === $niId && $ni2['payload_hash'] === $ni['payload_hash'], 'urgent row without id is kept with a stable digit-free id');

$small = IrisPublish::augment($sg);
$t($small['artifacts']['tool_report'] === 'report.txt' && !isset($small['result']['flagged_note']) && !isset($small['result']['groups_recorded']) && count($small['top_signatures']) === 1, 'cap: small document unchanged');
$t(array_key_exists('tool_report', $q['artifacts']) && $q['artifacts']['tool_report'] === null, 'fromRun tool_report is null');

$fat = $capDoc();
$fat['scope']['sites'] = array_map(fn($i) => sprintf('2%04d', $i), range(0, 19));
$fat['sites'] = [];
foreach ($fat['scope']['sites'] as $sid) {
    $fat['sites'][] = ['site_id' => $sid, 'roles_total' => 0, 'roles_ok' => 0, 'errors' => 0, 'warnings' => 0, 'roles' => []];
}
foreach ($fat['top_signatures'] as $i => $sig) {
    $fat['top_signatures'][$i]['signature'] = substr(sprintf('row %04d ', $i) . str_repeat('aaaa ', 400), 0, 2000);
    $fat['top_signatures'][$i]['locations'] = array_map(fn($sid) => $sid . '/admin', $fat['scope']['sites']);
    $fat['top_signatures'][$i]['count'] = 1000000 - $i;
}
$fat['urgent'] = [];
$fat['sites'][0]['roles'] = [];
$fatDoc = IrisPublish::augment($fat);
$t($body($fatDoc) <= $limit && count($fatDoc['top_signatures']) < 500 && count($fatDoc['top_signatures']) > 0, 'size loop: body fits after dropping from the end');
$t($fatDoc['payload_hash'] === IrisPublish::hash($fatDoc) && $valid($fatDoc), 'size loop: hash and schema hold');
$t(array_column($fatDoc['top_signatures'], 'rank') === range(1, count($fatDoc['top_signatures'])) && ($fatDoc['result']['groups_recorded'] ?? 0) === 501, 'size loop: ranks renumbered, groups recorded');
$t(substr_count((string)$fatDoc['result']['flagged_note'], 'Iris caps:') === 1, 'size loop: one note sentence');

// Duplicates inside the top slice must not cost a unique signature its slot.
$dup = $capDoc();
$dupRows = [];
for ($i = 0; $i < 10; $i++) {
    $dupRows[] = ['rank' => $i + 1, 'count' => 5000, 'level' => 'warning', 'severity' => 'medium', 'locations' => ['11111/admin'], 'signature' => 'dupsig-same'];
}
for ($i = 0; $i < 500; $i++) {
    $dupRows[] = ['rank' => 11 + $i, 'count' => 900 - $i, 'level' => 'warning', 'severity' => 'medium', 'locations' => ['11111/admin'], 'signature' => sprintf('uniq-%04d', $i)];
}
$dup['top_signatures'] = $dupRows;
$dupDoc = IrisPublish::augment($dup);
$dupSigs = array_column($dupDoc['top_signatures'], 'signature');
$t(count($dupSigs) === 500 && count(array_keys($dupSigs, 'dupsig-same', true)) === 1, 'dedupe before slice: 500 rows, duplicate once');
$t(in_array('uniq-0498', $dupSigs, true) && !in_array('uniq-0499', $dupSigs, true) && array_column($dupDoc['top_signatures'], 'rank') === range(1, 500), 'dedupe before slice: ranked-499 unique row kept, ranks renumbered');

// Sites alone over the limit, all four lists empty: the loop must keep dropping from the sites.
$ov = $capDoc();
$ov['top_signatures'] = [];
$ov['urgent'] = [];
$ov['suggested_fixes'] = [];
$ov['coverage_gaps'] = [];
$ov['scope']['sites'] = [];
$ov['sites'] = [];
for ($i = 0; $i < 60; $i++) {
    $sid = sprintf('3%04d', $i);
    $ov['scope']['sites'][] = $sid;
    $roles = [];
    for ($j = 0; $j < 50; $j++) {
        $roles[] = ['role' => sprintf('role-%02d', $j), 'status' => 'failed', 'duration_seconds' => 1, 'error' => ['detail' => str_repeat('abcd efgh ', 50)]];
    }
    $ov['sites'][] = ['site_id' => $sid, 'roles_total' => 50, 'roles_ok' => 0, 'errors' => 0, 'warnings' => 0, 'roles' => $roles];
}
$t($body($ov) > $limit, 'oversized sites: input exceeds the limit');
$ovDoc = IrisPublish::augment($ov);
$t($body($ovDoc) <= $limit, 'oversized sites: body fits after dropping roles and sites');
$t($ovDoc['payload_hash'] === IrisPublish::hash($ovDoc), 'oversized sites: payload_hash matches');
$ovNote = (string)($ovDoc['result']['flagged_note'] ?? '');
$t(substr_count($ovNote, 'Iris caps:') === 1 && str_contains($ovNote, 'dropped') && str_contains($ovNote, 'roles'), 'oversized sites: one note, counts roles');
$t($ovDoc['job'] === $ov['job'] && $ovDoc['timing'] === $ov['timing'], 'oversized sites: job and timing untouched');

$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(TOOL . '/fleet-log-scan.php');
$t(str_contains($help, '--iris-republish'), 'help mentions --iris-republish');
exec($cli . ' --iris-republish /tmp/x.iris.json --region sg 2>&1', $out7, $rc7);
$t($rc7 === 2 && !str_contains(strtolower(implode("\n", $out7)), 'scanning'), 'republish refuses --region');
exec($cli . ' --iris-republish /tmp/fls-no-such-file.iris.json 2>&1', $out8, $rc8);
$t($rc8 === 2, 'republish of a missing file exits 2');
$outside = sys_get_temp_dir() . '/fls-outside-' . getmypid() . '.iris.json';
file_put_contents($outside, '{}');
exec($cli . ' --iris-republish ' . escapeshellarg($outside) . ' 2>&1', $out9, $rc9);
$t($rc9 === 2, 'republish outside reports exits 2');
@unlink($outside);

if ($fail) {
    exit(1);
}
echo "iris-publish tests: $pass passed\n";
