<?php
declare(strict_types=1);

/*
 * fleet-log-scan — read-only Yii log scan across the fleet through the jump aliases.
 * See README section in the build report. Times shown in Asia/Manila; internals are epoch.
 *
 * Exit codes: 0 ok/quiet, 2 usage/config, 3 disabled, 4 lock busy, 5 scan failures,
 *             6 permissions too open, 7 live run refused (needs Dio's OK).
 */

namespace Fls;

umask(0077);
ini_set('display_errors', 'stderr');
error_reporting(E_ALL);

const TOOL_DIR = __DIR__;
foreach (['Util', 'Redact', 'Config', 'Payload', 'Sites', 'Pool', 'Tsv', 'State', 'Diff', 'Outputs', 'IrisPatterns', 'IrisPublish', 'SummaryNumberTrace', 'IrisSummaryVerifier', 'IrisSummary', 'Runner'] as $f) {
    require_once TOOL_DIR . '/lib/' . $f . '.php';
}

function usage(): string
{
    return <<<TXT
Usage:
  fleet-log-scan.php --daily                         daily scan: digest, or silence on a quiet day
  fleet-log-scan.php --site <id>                     one site, printed to the terminal
  fleet-log-scan.php --region jp|sg|vertex           one region
  fleet-log-scan.php --request-id <uuid> --site <id> [--from "YYYY-MM-DD HH:MM"] [--to "…"]   (Manila times)
  add --dry-run                                      no connections; show what would run; no state change
  add --fixtures <dir>                               run the payload locally against fixture logs (no SSH)
  add --webhook-dry-run                              print the webhook JSON instead of POSTing
  add --webhook-always                               send the webhook even on a quiet day
  add --iris-publish [--iris-sg <file>]              publish Iris ingest v1 instead of webhook.v1 (default off; quiet days publish too)
  add --iris-summary                                 with --iris-publish, attach a verified grok-4.7-high summary (default off)
  fleet-log-scan.php --iris-republish <file>         republish a saved *.iris.json with no SSH
Other: --config <file>  --per-run-ok (live trace only, after Dio approves)  --print-payload-hashes  --lint-payloads
Fixtures-only: --now <epoch>  --stagger <s>
Live SSH runs are refused unless config live.enabled is true (needs Dio's OK).
TXT;
}

function checkRepublishArgs(array $o): void
{
    $clash = $o['mode'] !== null ? ['another mode'] : [];
    foreach (['site', 'region', 'request_id', 'fixtures', 'iris_publish', 'iris_summary', 'iris_sg', 'dry_run'] as $k) {
        if (isset($o[$k])) {
            $clash[] = '--' . str_replace('_', '-', $k);
        }
    }
    if ($clash) {
        throw new FlsException('--iris-republish cannot be combined with ' . implode(', ', $clash), 2);
    }
    if (!str_ends_with($o['republish'], '.iris.json')) {
        throw new FlsException('--iris-republish needs a *.iris.json file', 2);
    }
}

/** The saved file must live inside data_dir/reports. */
function republishPath(array $cfg, string $file): string
{
    $real = realpath($file);
    $reports = realpath($cfg['data_dir'] . '/reports');
    if ($real === false || $reports === false || !is_file($real) || !str_starts_with($real, $reports . '/') || !str_ends_with($real, '.iris.json')) {
        throw new FlsException('--iris-republish file must be an existing *.iris.json inside the reports directory', 2);
    }
    return $real;
}

function parseArgs(array $argv): array
{
    $o = ['mode' => null];
    $need = static function (int &$i) use ($argv): string {
        if (!isset($argv[$i + 1])) {
            throw new FlsException('missing value for ' . $argv[$i], 2);
        }
        return $argv[++$i];
    };
    for ($i = 1; $i < count($argv); $i++) {
        $a = $argv[$i];
        switch ($a) {
            case '--daily': $o['mode'] = 'daily'; break;
            case '--site': $o['site'] = $need($i); $o['mode'] ??= 'site'; break;
            case '--region': $o['region'] = $need($i); $o['mode'] = 'region'; break;
            case '--request-id': $o['request_id'] = $need($i); $o['mode'] = 'trace'; break;
            case '--from': $o['from_s'] = $need($i); break;
            case '--to': $o['to_s'] = $need($i); break;
            case '--dry-run': $o['dry_run'] = true; break;
            case '--fixtures': $o['fixtures'] = $need($i); break;
            case '--webhook-dry-run': $o['webhook_dry_run'] = true; break;
            case '--webhook-always': $o['webhook_always'] = true; break;
            case '--iris-publish': $o['iris_publish'] = true; break;
            case '--iris-summary': $o['iris_summary'] = true; break;
            case '--iris-sg': $o['iris_sg'] = $need($i); break;
            case '--iris-republish': $o['republish'] = $need($i); break;
            case '--config': $o['config'] = $need($i); break;
            case '--per-run-ok': $o['per_run_ok'] = true; break;
            case '--now': $o['now_s'] = $need($i); break;
            case '--stagger': $o['stagger_s'] = $need($i); break;
            case '--print-payload-hashes': $o['mode'] = 'hashes'; break;
            case '--lint-payloads': $o['mode'] = 'lint'; break;
            case '-h': case '--help': $o['mode'] = 'help'; break;
            default: throw new FlsException('unknown argument: ' . preg_replace('/[^\w.:\/-]/', '?', $a), 2);
        }
    }
    if (isset($o['republish'])) {
        checkRepublishArgs($o);
        $o['mode'] = 'republish';
    }
    if ($o['mode'] === null) {
        throw new FlsException("no mode given\n" . usage(), 2);
    }
    if (isset($o['iris_sg']) && empty($o['iris_publish'])) {
        throw new FlsException('--iris-sg is only allowed with --iris-publish', 2);
    }
    if (!empty($o['iris_summary']) && empty($o['iris_publish'])) {
        throw new FlsException('--iris-summary is only allowed with --iris-publish', 2);
    }
    if (isset($o['site']) && !preg_match('/^\d{5}$/', $o['site'])) {
        throw new FlsException('--site must be a 5-digit site id', 2);
    }
    if (isset($o['region']) && !in_array($o['region'], ['jp', 'sg', 'vertex'], true)) {
        throw new FlsException('--region must be jp, sg or vertex', 2);
    }
    if (isset($o['fixtures'])) {
        $real = realpath($o['fixtures']);
        if ($real === false || !is_dir($real) || !preg_match('#^[A-Za-z0-9._/-]+$#', $real)) {
            throw new FlsException('--fixtures must be an existing directory with a simple path', 2);
        }
        $o['fixtures'] = $real;
    }
    foreach (['now_s' => 'now', 'stagger_s' => 'stagger'] as $k => $dst) {
        if (isset($o[$k])) {
            if (!isset($o['fixtures'])) {
                throw new FlsException('--' . $dst . ' is only allowed with --fixtures', 2);
            }
            if (!is_numeric($o[$k])) {
                throw new FlsException('--' . $dst . ' must be numeric', 2);
            }
            $o[$dst] = $dst === 'now' ? (int)$o[$k] : (float)$o[$k];
        }
    }
    foreach (['from_s' => 'from', 'to_s' => 'to'] as $k => $dst) {
        if (isset($o[$k])) {
            $e = Tz::parseManila($o[$k]);
            if ($e === null) {
                throw new FlsException('--' . $dst . ' must be "YYYY-MM-DD HH:MM" in Asia/Manila', 2);
            }
            $o[$dst] = $e;
        }
    }
    return $o;
}

const REPORTER_AUTOLOAD = '/Users/diorti/Documents/codes/rti/fleet-reporter/vendor/autoload.php';
const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

/** @return list<string> "pointer rule" lines from the reporter's own checks. No values. */
function republishViolations(array $doc): array
{
    $obj = json_decode((string)json_encode($doc, JSON_FLAGS));
    $out = [];
    foreach ((new \app\services\SchemaValidator())->validate($obj) as $v) {
        $out[] = $v['pointer'] . ' ' . $v['rule'];
    }
    foreach ((new \app\support\Redactor())->scan($obj) as $h) {
        $out[] = $h['pointer'] . ' ' . $h['class'];
    }
    $hash = $doc['payload_hash'] ?? null;
    if ($hash !== IrisPublish::hash($doc) || $hash !== \app\support\Canonical::hash($obj)) {
        $out[] = '/payload_hash hash_mismatch';
    }
    if (strlen((string)json_encode($doc, JSON_FLAGS)) > 1048576) {
        $out[] = '/ too_large';
    }
    return $out;
}

/** 422 body: print "pointer rule" or "pointer class" lines only. */
function republishRejected(array $res): void
{
    $body = json_decode((string)($res['body'] ?? ''), true);
    if (!is_array($body)) {
        return;
    }
    foreach (['violations' => 'rule', 'hits' => 'class'] as $key => $field) {
        foreach (is_array($body[$key] ?? null) ? array_slice($body[$key], 0, 100) : [] as $v) {
            if (is_array($v) && is_string($v['pointer'] ?? null) && is_string($v[$field] ?? null)) {
                echo $v['pointer'], ' ', $v[$field], "\n";
            }
        }
    }
}

function republish(array $cfg, string $file): int
{
    $doc = json_decode((string)file_get_contents($file), true);
    if (!is_array($doc) || $doc === [] || array_is_list($doc)) {
        fwrite(STDERR, "fleet-log-scan: republish file is not a JSON object\n");
        return 2;
    }
    $doc = IrisPublish::augment($doc);
    if (!is_file(REPORTER_AUTOLOAD)) {
        fwrite(STDERR, "fleet-log-scan: fleet-reporter autoload not found\n");
        return 2;
    }
    require_once REPORTER_AUTOLOAD;
    $bad = republishViolations($doc);
    if ($bad) {
        echo implode("\n", $bad), "\n";
        return 2;
    }
    $sent = IrisPublish::remember($file, $doc, true);
    $wh = Webhook::fromEnvFile($cfg['webhook_env']);
    $res = $wh->postResult($sent);
    echo $wh->mask($res['status']), "\n";
    if ($res['code'] === 422) {
        republishRejected($res);
    }
    return $res['code'] >= 200 && $res['code'] < 300 ? 0 : 5;
}

function main(array $argv): int
{
    try {
        $o = parseArgs($argv);
        if ($o['mode'] === 'help') {
            echo usage(), "\n";
            return 0;
        }
        if ($o['mode'] === 'hashes' || $o['mode'] === 'lint') {
            $rc = 0;
            foreach (array_keys(Payload::ARG_KEYS) as $p) {
                $src = (string)file_get_contents(TOOL_DIR . '/payload/' . $p);
                if ($o['mode'] === 'hashes') {
                    echo hash('sha256', $src), '  ', $p, "\n";
                } else {
                    $l = Payload::lint($src);
                    echo $p, ': ', $l ? 'FAIL ' . implode(', ', $l) : 'ok', "\n";
                    $rc = $l ? 2 : $rc;
                }
            }
            return $rc;
        }
        $cfg = Config::load($o['config'] ?? TOOL_DIR . '/config.php', TOOL_DIR);
        $data = $cfg['data_dir'];
        if ($o['mode'] === 'republish') {
            $o['republish'] = republishPath($cfg, $o['republish']);
        }
        foreach (['state', 'state/checkpoints', 'state/groups', 'scratch', 'reports', 'outbox'] as $d) {
            Fs::ensureDir($data . '/' . $d);
        }
        $loose = Fs::loosePerms($data, ['state', 'scratch', 'reports', 'outbox', 'webhook.env']);
        if (!is_file($o['config'] ?? '') && (fileperms(TOOL_DIR . '/config.php') & 0077)) {
            $loose[] = 'config.php';
        }
        if ($loose) {
            fwrite(STDERR, "refusing to run: group/world-accessible paths: " . implode(', ', array_slice($loose, 0, 10)) . " (need dirs 0700, files 0600)\n");
            return 6;
        }
        if ($o['mode'] === 'daily' && is_file($data . '/state/DISABLED') && empty($o['dry_run']) && !isset($o['fixtures'])) {
            echo "fleet-log-scan: daily run disabled (state/DISABLED present). Nothing scanned.\n";
            return 3;
        }
        $lock = new Lock($data . '/state/run.lock');
        if (!$lock->acquire()) {
            fwrite(STDERR, "another fleet-log-scan run is in progress (run.lock); not starting a second one\n");
            return 4;
        }
        try {
            if ($o['mode'] === 'republish') {
                return republish($cfg, $o['republish']);
            }
            $r = new Runner($cfg, $o);
            return $o['mode'] === 'trace' ? $r->trace() : $r->scan();
        } finally {
            $lock->release();
        }
    } catch (FlsException $e) {
        fwrite(STDERR, 'fleet-log-scan: ' . $e->getMessage() . "\n");
        return $e->getCode() ?: 2;
    } catch (\Throwable $e) {
        // Do not echo raw exception text (could carry paths/addresses); class + line only.
        fwrite(STDERR, 'fleet-log-scan: internal error ' . get_class($e) . ' at ' . basename($e->getFile()) . ':' . $e->getLine() . "\n");
        return 2;
    }
}

exit(main($argv));
