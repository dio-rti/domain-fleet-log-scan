<?php
declare(strict_types=1);

// Test helpers for fleet-log-scan. Synthetic data only. Never calls real ssh/global/cursor-agent/launchctl.

const PHP_BIN = '/opt/homebrew/bin/php';
define('TOOL', dirname(__DIR__));
foreach (['Util', 'Redact', 'Config', 'Payload', 'Sites', 'Pool', 'Tsv', 'State', 'Family', 'Diff', 'Outputs', 'IrisPatterns', 'IrisPublish', 'SummaryNumberTrace', 'IrisSummaryVerifier', 'IrisSummary', 'Runner'] as $f) {
    require_once TOOL . '/lib/' . $f . '.php';
}

/** Planted fake secrets/addresses. None of these may appear in any tool output. */
const PLANTED = [
    '198.51.100.23', '203.0.113.77', '192.0.2.10', '2001:db8::dead:beef',
    'csrfFAKEvalue9Q8W7E6R5T4Y3U2I1O0P', 'fakesess0123456789abcdefghij', 'FAKEidentityCOOKIE123456789',
    'player@example.com', 'fake.user@example.test', '09175550199', '917 555 0199',
    'FAKEtoken0123456789abcdefXYZ', 'eyJhbGciOiJIUzI1NiJ9', 'FakePass!123', 'api.fake-casino.com',
    // fake addresses returned by the fake global CLI
    '198.51.100.201', '198.51.100.202', '198.51.100.203', '198.51.100.204', '203.0.113.205', '203.0.113.206',
    '203.0.113.207', '203.0.113.208', '192.0.2.209', '192.0.2.210', '192.0.2.211',
    // webhook secret
    'whsecret-FAKE-0123456789',
];

final class T
{
    public static int $pass = 0;
    public static int $fail = 0;
    public static array $failures = [];
    public static string $section = '';

    public static function section(string $s): void
    {
        self::$section = $s;
        echo "\n== $s\n";
    }

    public static function ok(bool $c, string $msg): void
    {
        if ($c) {
            self::$pass++;
            echo "  ok   $msg\n";
        } else {
            self::$fail++;
            self::$failures[] = self::$section . ': ' . $msg;
            echo "  FAIL $msg\n";
        }
    }

    public static function eq($a, $b, string $msg): void
    {
        self::ok($a === $b, $msg . ($a === $b ? '' : ' (got ' . json_encode($a) . ', want ' . json_encode($b) . ')'));
    }

    public static function contains(string $hay, string $needle, string $msg): void
    {
        self::ok(str_contains($hay, $needle), $msg . (str_contains($hay, $needle) ? '' : ' (missing "' . $needle . '")'));
    }

    public static function notContains(string $hay, string $needle, string $msg): void
    {
        self::ok(!str_contains($hay, $needle), $msg);
    }
}

function tmpdir(string $base, string $name): string
{
    $d = $base . '/' . $name;
    if (is_dir($d)) {
        Fls\Fs::rmTree($d);
    }
    mkdir($d, 0700, true);
    return $d;
}

/** One Yii log line block. $ts is server-local (KST). */
function entry(string $ts, string $level, string $cat, string $msg, array $extra = []): string
{
    $s = $ts . ' [198.51.100.23][77][fakesess0123456789abcdefghij][' . $level . '][' . $cat . '] ' . $msg . "\n";
    foreach ($extra as $e) {
        $s .= $e . "\n";
    }
    return $s;
}

function kst(int $epoch): string
{
    return (new DateTimeImmutable('@' . $epoch))->setTimezone(new DateTimeZone('Asia/Seoul'))->format('Y-m-d H:i:s');
}

function appendLog(string $file, string $data): void
{
    if (!is_dir(dirname($file))) {
        mkdir(dirname($file), 0700, true);
    }
    file_put_contents($file, $data, FILE_APPEND);
}

/** Spread $n entries over ($from, $to] seconds. */
function spread(int $from, int $to, int $n, callable $make): string
{
    $s = '';
    for ($i = 0; $i < $n; $i++) {
        $t = $from + (int)(($to - $from) * ($i + 1) / ($n + 1));
        $s .= $make(kst($t), $i);
    }
    return $s;
}

function cookieDump(string $ts): string
{
    return $ts . " [198.51.100.23][-][fakesess0123456789abcdefghij][info][application] \$_COOKIE = [\n"
        . "    '_csrf' => 'csrfFAKEvalue9Q8W7E6R5T4Y3U2I1O0P'\n    'PHPSESSID' => 'fakesess0123456789abcdefghij'\n"
        . "    '_identity' => 'FAKEidentityCOOKIE123456789'\n]\n"
        . $ts . " [198.51.100.23][-][fakesess0123456789abcdefghij][info][application] \$_SERVER = [\n"
        . "    'REMOTE_ADDR' => '203.0.113.77'\n    'HTTP_HOST' => 'api.fake-casino.com'\n]\n";
}

/** Run the CLI. Returns [exit, stdout, stderr]. PATH is prefixed with the trap dir. */
function cli(array $args, array $env = [], ?string $trap = null, int $timeout = 300): array
{
    $e = getenv();
    if ($trap) {
        $e['PATH'] = $trap . ':' . ($e['PATH'] ?? '/usr/bin:/bin');
    }
    foreach ($env as $k => $v) {
        $e[$k] = $v;
    }
    $r = Fls\Proc::run([PHP_BIN, TOOL . '/fleet-log-scan.php', ...$args], '', $timeout, TOOL, $e);
    return [$r['exit'], $r['stdout'], $r['stderr']];
}

function writeConfig(string $path, array $over): string
{
    $base = [
        'data_dir' => dirname($path) . '/data',
        'global_cli' => ['enabled' => false, 'bin' => '/nonexistent/global'],
        'model' => ['enabled' => false, 'name' => 'grok-4.7-xhigh-fast', 'bin' => '/nonexistent/cursor-agent'],
        'ssh_bin' => '/nonexistent/ssh',
        'webhook_env' => dirname($path) . '/webhook.env',
    ];
    $c = array_replace_recursive($base, $over);
    file_put_contents($path, "<?php\nreturn " . var_export($c, true) . ";\n");
    chmod($path, 0600);
    @mkdir($c['data_dir'] . '/state', 0700, true);
    copy(TOOL . '/state/known-harmless.json', $c['data_dir'] . '/state/known-harmless.json');
    chmod($c['data_dir'] . '/state/known-harmless.json', 0600);
    return $path;
}

/** All text a run left behind (reports, state, outbox) + given extra strings. */
function allOutput(string $dataDir, array $extra = []): string
{
    $s = implode("\n", $extra);
    if (is_dir($dataDir)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dataDir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile()) {
                $s .= "\n" . file_get_contents($f->getPathname());
            }
        }
    }
    return $s;
}

/** Copy the tool scripts into a work dir so tests can tamper a hash without touching the real pin. */
function copyTool(string $base, string $name): string
{
    $d = tmpdir($base, $name);
    foreach (['lib', 'payload'] as $sub) {
        mkdir("$d/$sub", 0700);
        foreach (glob(TOOL . "/$sub/*") ?: [] as $f) {
            if (is_file($f)) {
                copy($f, "$d/$sub/" . basename($f));
            }
        }
    }
    copy(TOOL . '/fleet-log-scan.php', "$d/fleet-log-scan.php");
    copy(TOOL . '/config.php', "$d/config.php");
    return $d;
}

/**
 * Classes still visible in text. Placeholders are stripped first so {secret}/{hex}/{n} are quiet.
 * Bearer is checked on the original so "bearer {token}" stays quiet and a raw token does not.
 * No blanket 7-digit match: epochs and inodes live in state JSON.
 * @return string[]
 */
function leakClasses(string $text): array
{
    $hits = [];
    if (preg_match('/\bbearer\s+(?!\{)(?:"[^"]+"|\'[^\']+\'|\S+)/i', $text)) {
        $hits[] = 'bearer';
    }
    $stripped = str_replace(
        ['{secret}', '{token}', '{hex}', '{n}', '{b64}', '{ip}', '{host}', '{email}', '{jwt}', '{uuid}', '{url}'],
        ' ',
        $text
    );
    $rules = [
        'ipv4' => '/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/',
        'csrf' => '/_csrf/i',
        'session-id' => '/phpsessid/i',
        'jwt' => '/eyJ[\w-]{8,}\.[\w-]{8,}\./',
        'email' => '/[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}/i',
        'phone' => '/(?<!\d)0\d{9,11}(?!\d)|\b\d{3}\s+\d{3}\s+\d{4}\b/',
        'hostname' => '/(?<![A-Za-z0-9@_-])(?:[a-z0-9-]+\.)+(?!(?:' . Fls\Redact::EXTS . ')\b)(?:' . Fls\Redact::TLDS . '|[a-z]{2,3})(?![a-z0-9])/i',
        'split' => '/\{(?:hex|n|b64)\}[A-Za-z0-9+\/]{4,}|[A-Za-z0-9+\/]{4,}\{(?:hex|n|b64)\}/',
    ];
    foreach ($rules as $name => $re) {
        if (preg_match($re, $name === 'split' ? $text : $stripped)) {
            $hits[] = $name;
        }
    }
    if (preg_match_all('/[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*(?![A-Za-z0-9])/i', $stripped, $mm)) {
        foreach ($mm[0] as $t) {
            if (Fls\Redact::isIpv6Token($t)) {
                $hits[] = 'ipv6';
                break;
            }
        }
    }
    return $hits;
}

function assertNoLeaks(string $text, string $what): void
{
    $hits = 0;
    foreach (PLANTED as $p) {
        if ($p !== '' && stripos($text, $p) !== false) {
            $hits++;
        }
    }
    T::ok($hits === 0, "no planted secret/address in $what" . ($hits ? " (found $hits)" : ''));
    $cls = leakClasses($text);
    T::ok(!$cls, "no redaction-class pattern in $what" . ($cls ? ' ' . implode(',', $cls) : ''));
}

function permsOk(string $dir): array
{
    $bad = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $f) {
        $m = fileperms($f->getPathname()) & 0777;
        if (($f->isDir() && $m !== 0700) || ($f->isFile() && $m !== 0600)) {
            $bad[] = substr($f->getPathname(), strlen($dir)) . sprintf(' %o', $m);
        }
    }
    return $bad;
}

/** Start `php -S` webhook listener on an ephemeral loopback port. */
function startListener(string $dir): array
{
    $router = $dir . '/router.php';
    file_put_contents($router, <<<'PHP'
<?php
$dir = __DIR__ . '/captures';
@mkdir($dir, 0700, true);
$n = count(glob($dir . '/*.json')) + 1;
file_put_contents($dir . "/$n.json", json_encode(['uri' => $_SERVER['REQUEST_URI'], 'method' => $_SERVER['REQUEST_METHOD'],
  'auth' => $_SERVER['HTTP_AUTHORIZATION'] ?? null, 'ctype' => $_SERVER['CONTENT_TYPE'] ?? null, 'body' => file_get_contents('php://input')]));
if (str_starts_with($_SERVER['REQUEST_URI'], '/slow')) { sleep(15); }
if (str_starts_with($_SERVER['REQUEST_URI'], '/fail')) { http_response_code(500); echo 'no'; return; }
http_response_code(204);
PHP);
    for ($i = 0; $i < 20; $i++) {
        $port = random_int(20000, 45000);
        $p = proc_open([PHP_BIN, '-S', '127.0.0.1:' . $port, $router], [0 => ['pipe', 'r'], 1 => ['file', $dir . '/server.log', 'a'], 2 => ['file', $dir . '/server.log', 'a']], $pipes, $dir, getenv() + ['PHP_CLI_SERVER_WORKERS' => '4']);
        for ($j = 0; $j < 30; $j++) {
            usleep(100000);
            $s = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
            if ($s) {
                fclose($s);
                return [$p, $port];
            }
        }
        proc_terminate($p);
    }
    throw new RuntimeException('listener did not start');
}

function captures(string $dir): array
{
    $out = [];
    foreach (glob($dir . '/captures/*.json') ?: [] as $f) {
        $out[] = json_decode(file_get_contents($f), true);
    }
    return $out;
}

function clearCaptures(string $dir): void
{
    foreach (glob($dir . '/captures/*.json') ?: [] as $f) {
        unlink($f);
    }
}

function writeWebhookEnv(string $path, string $url, string $extra = ''): void
{
    file_put_contents($path, "WEBHOOK_URL=$url\nWEBHOOK_AUTH_HEADER=Bearer whsecret-FAKE-0123456789\n$extra");
    chmod($path, 0600);
}

/** Trap dir: fake ssh/scp/global/cursor-agent/launchctl/curl/wget that only record that they were called. */
function makeTrap(string $dir): string
{
    $t = $dir . '/trap';
    @mkdir($t, 0700, true);
    foreach (['ssh', 'scp', 'sftp', 'global', 'global-cli', 'cursor-agent', 'launchctl', 'curl', 'wget', 'nc', 'openclaw'] as $b) {
        file_put_contents("$t/$b", "#!/bin/sh\necho \"$b\" >> '$t/TRIPPED'\nexit 99\n");
        chmod("$t/$b", 0700);
    }
    return $t;
}
