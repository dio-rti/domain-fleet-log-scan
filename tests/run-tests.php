<?php
declare(strict_types=1);

// fleet-log-scan local test suite. LOCAL FIXTURES ONLY: no SSH to any jump/app server, no production reads,
// no real global/cursor-agent calls, webhook only to a php -S listener on 127.0.0.1.
// Usage: php tests/run-tests.php [--work <dir>] [--skip-docker]

require __DIR__ . '/lib.php';

use Fls\{Redact, Payload, Pool, Tsv, SiteSource, ServerList, Config, Webhook, Summary, Diff, Fs, Tz};

$opts = getopt('', ['work:', 'skip-docker']);
$WORK = $opts['work'] ?? (getenv('HOME') . '/.openclaw/workspace-abella/tmp/fleet-log-scan-build/test-work');
@mkdir($WORK, 0700, true);
$WORK = realpath($WORK);
$TRAP = makeTrap($WORK);
@unlink($TRAP . '/TRIPPED');
$STUBS = TOOL . '/tests/stubs';
$t0 = microtime(true);

// ---------------------------------------------------------------- 1. lint / hash / args
T::section('payload lint, hash, args');
foreach (['scan-v1.sh', 'trace-v1.sh'] as $p) {
    T::eq(Payload::lint((string)file_get_contents(TOOL . "/payload/$p")), [], "$p lints clean");
    T::ok(strlen(Payload::load(TOOL, $p)) > 1000, "$p hash matches payload.sha256");
}
$forbidden = [
    'echo x > /tmp/f' => '>', 'echo x >> f' => '>>', 'rm -f app.log' => 'rm', 'mv a b' => 'mv', 'cp a b' => 'cp',
    "sed -i 's/a/b/' f" => 'sed -i', 'echo x | tee f' => 'tee', 'php yii migrate' => 'yii', 'mysql -e "drop"' => 'mysql',
    'curl http://x' => 'curl', 'wget http://x' => 'wget', 'kill 1' => 'kill', 'chmod 777 f' => 'chmod',
    'bash -c "id"' => 'nested shell', 'cat f | sh' => 'nested shell', 'awk \'{system("id")}\'' => 'system',
    'awk \'{ "id" | getline x }\'' => 'getline', "sed 's/a/b/w out' f" => 'sed w', 'truncate -s0 f' => 'truncate',
    "sed 's/a/b/e' f" => 'sed e',
    'python -c "print(1)"' => 'python', 'python3 -c "print(1)"' => 'python3',
    'perl -e "print 1"' => 'perl', 'php -r "echo 1;"' => 'php',
    'ruby -e "puts 1"' => 'ruby', 'node -e "console.log(1)"' => 'node', 'nodejs -e 1' => 'nodejs',
];
foreach ($forbidden as $src => $what) {
    T::ok(Payload::lint("#!/bin/bash\n$src\n") !== [], "lint rejects $what");
}
T::eq(Payload::lint("#!/bin/bash\nsed -e 's/a/b/' f\n"), [], 'lint allows the sed -e script flag');
$tmpTool = tmpdir($WORK, 'tooldir-copy');
mkdir("$tmpTool/payload", 0700);
copy(TOOL . '/payload/payload.sha256', "$tmpTool/payload/payload.sha256");
file_put_contents("$tmpTool/payload/scan-v1.sh", file_get_contents(TOOL . '/payload/scan-v1.sh') . "\n# tampered\n");
try {
    Payload::load($tmpTool, 'scan-v1.sh');
    T::ok(false, 'tampered payload refused');
} catch (Fls\FlsException $e) {
    T::contains($e->getMessage(), 'hash mismatch', 'tampered payload refused (hash mismatch)');
}
foreach ([[['root', '/x'], false, 'root= refused outside fixtures'], [['since', '1;id'], false, 'bad value refused'], [['evil', '1'], false, 'unknown key refused'], [['ck', 'a b'], false, 'space refused']] as [$kv, $root, $msg]) {
    try {
        Payload::args('scan-v1.sh', [$kv], $root);
        T::ok(false, $msg);
    } catch (Fls\FlsException) {
        T::ok(true, $msg);
    }
}
T::eq(Payload::args('scan-v1.sh', [['root', '/tmp/x'], ['since', '5']], true), ['root=/tmp/x', 'since=5'], 'root= allowed in fixtures mode');

// ---------------------------------------------------------------- 2. redaction + tripwire
T::section('redaction (PHP pass) and tripwire');
$raw = 'login fail player@example.com from 198.51.100.23 / 2001:db8::dead:beef token=FAKEtoken0123456789abcdefXYZ '
    . 'Cookie: _csrf=csrfFAKEvalue9Q8W7E6R5T4Y3U2I1O0P; PHPSESSID=fakesess0123456789abcdefghij';
$r = Redact::pass($raw);
assertNoLeaks($r, 'PHP redaction pass output');
T::eq(Redact::tripwire($r), null, 'tripwire quiet on redacted text');
$r2 = Redact::pass('Bearer FAKEtoken0123456789abcdefXYZ jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl phone 09175550199 host api.fake-casino.com uuid 11111111-2222-4333-8444-555555555555 password=FakePass!123');
assertNoLeaks($r2, 'PHP redaction pass output (tokens)');
T::eq(Redact::tripwire($r2), null, 'tripwire quiet on redacted tokens');
$keep = Redact::pass('yii\db\Exception: Fork child failed in /var/www/domain-0/components/BaseProcessController.php:305 Foo::bar HttpException:500');
T::contains($keep, 'BaseProcessController.php:305', 'File.php:line kept');
T::contains($keep, 'Foo::bar', 'Class::method kept');
T::contains($keep, 'HttpException:500', '5xx status kept');
T::eq(Redact::tripwire($keep), null, 'tripwire quiet on class/file:line text');
foreach (['raw 203.0.113.77' => 'ipv4', 'x _csrf y' => 'csrf', 'PHPSESSID' => 'session-id', 'a@b.example.com' => 'email',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.sig' => 'jwt', 'k QmFzZTY0U3RyaW5nV2l0aERpZ2l0czEyMzQ1Njc4OTA=' => 'base64',
    'token=abc' => 'secret-kv', 'fe80:0:0:0:1:2:3:4' => 'ipv6', '09175550199' => 'long-digits', 'Cookie: a=b' => 'cookie'] as $leak => $cls) {
    T::eq(Redact::tripwire($leak), $cls, "tripwire fires on planted $cls");
}
$tsv = Tsv::parse("H\tscan-v1\t1\t+0900\tservice\nG\t-\terror\tapp\tleaked _csrf mismatch\t3\ta\tb\tapp.log\nG\t-\twarning\tapp\tclean {n}\t2\ta\tb\tapp.log\nE\tscan-v1\tok\n");
T::eq([$tsv->tripwire, count($tsv->groups)], [1, 1], 'Tsv drops the leaking row and keeps the clean one');

$tok = 'zzNotHexToken.short';
$bearer = "Authorization: Bearer $tok";
$httpAuth = "'HTTP_AUTHORIZATION' => 'Bearer $tok'";
$pw = 'password=zzWordOne zzWordTwo';
T::ok(in_array('bearer', leakClasses($bearer), true), 'leak oracle flags a raw Authorization bearer');
T::ok(in_array('bearer', leakClasses($httpAuth), true), 'leak oracle flags a raw HTTP_AUTHORIZATION bearer');
foreach (['auth header' => $bearer, 'http auth' => $httpAuth] as $label => $src) {
    $red = Redact::pass($src);
    T::ok(!str_contains($red, $tok), "php redacts the bearer token ($label)");
    T::eq(Redact::tripwire($red), null, "tripwire quiet on redacted bearer ($label)");
    T::eq(leakClasses($red), [], "leak oracle quiet on redacted bearer ($label)");
}
T::eq(Redact::tripwire($bearer), 'bearer', 'tripwire catches a leftover bearer token');
$redPw = Redact::pass($pw);
T::ok(!str_contains($redPw, 'zzWordOne') && !str_contains($redPw, 'zzWordTwo'), 'php redacts a password value that contains a space');
T::eq(Redact::tripwire($redPw), null, 'tripwire quiet on a redacted spaced password');
T::eq(Redact::tripwire($pw), 'secret-kv', 'tripwire still flags an unredacted password');
$net = Redact::pass('loopback ::1 and host a.b.uk and school c.d.edu');
T::ok(!str_contains($net, '::1') && !str_contains($net, '.uk') && !str_contains($net, '.edu'), 'php redacts ::1 and .uk/.edu hosts');
T::eq(Redact::tripwire($net), null, 'tripwire quiet after ipv6 and host redaction');
T::eq(Redact::tripwire('loopback ::1'), 'ipv6', 'tripwire catches ::1');
T::eq(Redact::tripwire('see a.b.uk now'), 'hostname', 'tripwire catches a .uk host');
T::eq(Redact::tripwire('see c.d.edu now'), 'hostname', 'tripwire catches a .edu host');

$zone = date_default_timezone_get();
date_default_timezone_set('Asia/Dubai');
try {
    $manila = (new DateTimeImmutable('2026-11-13 08:00:00', new DateTimeZone('Asia/Manila')))->getTimestamp();
    $utc = (new DateTimeImmutable('2026-11-13 08:00:00', new DateTimeZone('UTC')))->getTimestamp();
    $dubai = (new DateTimeImmutable('2026-11-13 08:00:00', new DateTimeZone('Asia/Dubai')))->getTimestamp();
    T::eq(Tz::parseManila('2026-11-13 08:00'), $manila, 'parseManila is Manila when the process zone is Dubai');
    T::ok($manila !== $utc && $manila !== $dubai, 'that Manila epoch is neither the UTC nor the Dubai instant');
    T::eq(Tz::parseManila('2026-11-13 08:00:00'), $manila, 'parseManila with seconds matches the same Manila instant');
    T::eq(Tz::parseManila('2026-11-13'), (new DateTimeImmutable('2026-11-13 00:00:00', new DateTimeZone('Asia/Manila')))->getTimestamp(), 'date-only parseManila is Manila midnight');
    T::eq(Tz::parseManila('2026-02-31'), null, 'invalid calendar date is rejected');
    $seoul = Tz::serverTsToEpoch('2026-11-13 08:00:00', '+0900');
    T::eq($seoul, (new DateTimeImmutable('2026-11-13 08:00:00 +0900'))->getTimestamp(), 'server +0900 conversion stays on the offset path');
    T::ok($seoul !== $manila, 'server +0900 and Manila wall time are different instants');
} finally {
    date_default_timezone_set($zone);
}

$kh = Fls\KnownHarmless::load(['data_dir' => $WORK . '/no-kh', 'tool_dir' => TOOL]);
T::eq($kh->match('10010', 'db', 'warning', 'app', 'Sports socket JSON decode failed: context=client-data len={n}'), 'sports-socket-partial-frame', 'sports-socket wording still matches');
T::eq($kh->match('10010', 'db', 'warning', 'app', 'cache _decodeJson failed for a new feed'), null, 'bare _decodeJson is not known-harmless');
T::eq($kh->match('30030', 'admin', 'warning', 'application', 'admin login failed from the console'), 'admin-login-audit', 'login-audit wording still matches');
T::eq($kh->match('30030', 'admin', 'warning', 'application', 'login page asset missing'), null, 'bare login is not known-harmless');

// ---------------------------------------------------------------- 3. payload checkpoint table (direct, macOS bash 3.2 + BWK awk)
T::section('payload checkpoints (section 5 table)');
function runScan(string $root, array $args, string $role = 'service'): Tsv
{
    $r = Fls\Proc::run(['/bin/bash', '-s', '--', "role=$role", ...$args, "root=$root"], (string)file_get_contents(TOOL . '/payload/scan-v1.sh'), 60, null, ['TZ' => 'Asia/Seoul', 'PATH' => '/usr/bin:/bin', 'LC_ALL' => 'C']);
    return Tsv::parse($r['stdout']);
}
function inodeOf(string $f): string
{
    clearstatcache();
    return (string)fileinode($f);
}
function cnt(Tsv $t, string $needle): int
{
    $n = 0;
    foreach ($t->groups as $g) {
        if (str_contains($g['template'], $needle)) {
            $n += $g['count'];
        }
    }
    return $n;
}
$now = time() - 600;
$since = $now - 86400;
$cpd = tmpdir($WORK, 'cp');
$app = "$cpd/app.log";
// first run: bounded by entry ts to the last 24 h; rotated .1 and recent .gz included, old .gz excluded
file_put_contents("$cpd/app.log.1", entry(kst($now - 90000), 'error', 'app', 'Too old entry') . spread($now - 80000, $now - 70000, 5, fn($ts) => entry($ts, 'warning', 'app', 'Rotated one entry')));
file_put_contents("$cpd/tmp.log", spread($now - 60000, $now - 50000, 4, fn($ts) => entry($ts, 'warning', 'app', 'Gz rotated entry')));
Fls\Proc::run(['/bin/sh', '-c', 'gzip -c tmp.log | cat > app.log.2.gz.tmp'], '', 10, $cpd);
rename("$cpd/app.log.2.gz.tmp", "$cpd/app.log.2.gz");
file_put_contents("$cpd/tmp.log", entry(kst($now - 3600), 'warning', 'app', 'Stale gz entry'));
Fls\Proc::run(['/bin/sh', '-c', 'gzip -c tmp.log | cat > app.log.3.gz.tmp'], '', 10, $cpd);
rename("$cpd/app.log.3.gz.tmp", "$cpd/app.log.3.gz");
touch("$cpd/app.log.3.gz", $now - 4 * 86400);
unlink("$cpd/tmp.log");
file_put_contents($app, "leading partial bytes\n" . spread($now - 40000, $now - 30000, 3, fn($ts) => entry($ts, 'error', 'yii\db\Exception', 'Fork child failed in /var/www/x/BaseProcessController.php:305', ['Stack trace:', '#0 /var/www/x/a.php(12): f()']))
    . entry(kst($now - 20000), 'warning', 'app', 'A one') . rtrim(entry(kst($now - 19999), 'warning', 'app', 'B concatenated'), "\n") . entry(kst($now - 19998), 'warning', 'app', 'C after concat'));
$t = runScan($cpd, ["since=$since", 'max=52428800']);
T::ok($t->complete && $t->error === null, 'first run completes (E record)');
T::eq(cnt($t, 'Too old'), 0, 'first run: entries older than 24 h excluded');
T::eq(cnt($t, 'Rotated one'), 5, 'first run: recent rotated app.log.1 read');
T::eq(cnt($t, 'Gz rotated'), 4, 'first run: recent .gz read');
T::eq(cnt($t, 'Stale gz'), 0, 'first run: .gz older than the window skipped by mtime');
T::eq(cnt($t, 'Fork child failed'), 3, 'multi-line traces counted once per entry');
T::eq([cnt($t, 'A one'), cnt($t, 'B concatenated'), cnt($t, 'C after concat')], [1, 1, 1], 'concatenated entries split');
T::eq($t->files['app.log']['flags'], ['first'], 'first run flagged first');
T::eq($t->files['app.log']['offset'], (string)filesize($app), 'offset = snapshot size');
$ck = function (Tsv $t): string {
    $f = $t->files['app.log'];
    $s = 'ck=app.log:' . $f['inode'] . ':' . $f['offset'] . ':' . (Tz::serverTsToEpoch($f['last_ts'], '+0900') ?? 0);
    if (($f['prefix_len'] ?? 0) > 0 && preg_match('/^\d+$/', (string)$f['prefix_sum'])) {
        $s .= ':' . $f['prefix_len'] . ':' . $f['prefix_sum'];
    }
    return $s;
};
// same inode append
$c1 = $ck($t);
appendLog($app, spread($now - 500, $now - 400, 2, fn($ts) => entry($ts, 'warning', 'app', 'Delta entry')));
$t2 = runScan($cpd, ["since=$since", 'max=52428800', $c1]);
T::eq([cnt($t2, 'Delta entry'), cnt($t2, 'Fork child'), $t2->files['app.log']['flags']], [2, 0, []], 'same inode: only the delta is read');
T::eq($t2->files['app.log']['offset'], (string)filesize($app), 'same inode: checkpoint advances to new size');
// truncation
$c2 = $ck($t2);
file_put_contents($app, entry(kst($now - 300), 'warning', 'app', 'After truncate'));
$t3 = runScan($cpd, ["since=$since", 'max=52428800', $c2]);
T::eq([cnt($t3, 'After truncate'), $t3->files['app.log']['flags']], [1, ['truncated']], 'truncated: read from 0 and flagged');
// rotation by rename
$c3 = $ck($t3);
appendLog($app, entry(kst($now - 250), 'warning', 'app', 'Tail before rotate'));
rename("$cpd/app.log.1", "$cpd/app.log.4");
rename($app, "$cpd/app.log.1");
file_put_contents($app, entry(kst($now - 200), 'warning', 'app', 'New file after rotate'));
$t4 = runScan($cpd, ["since=$since", 'max=52428800', $c3]);
T::eq([cnt($t4, 'Tail before rotate'), cnt($t4, 'New file after rotate'), cnt($t4, 'After truncate'), $t4->files['app.log']['flags']], [1, 1, 0, ['rotated']], 'rotation: old inode remainder + new file from 0');
T::eq($t4->files['app.log']['inode'], inodeOf($app), 'rotation: checkpoint moves to the new inode');
// inode changed and old inode gone (gap)
$c4 = $ck($t4);
foreach (glob("$cpd/app.log*") as $f) {
    unlink($f);
}
file_put_contents($app, entry(kst($now - 100000), 'warning', 'app', 'Ancient') . entry(kst($now - 150), 'warning', 'app', 'After gap'));
$t5 = runScan($cpd, ["since=$since", 'max=52428800', $c4]);
T::eq([cnt($t5, 'After gap'), cnt($t5, 'Ancient'), $t5->files['app.log']['flags']], [1, 0, ['gap']], 'gap: flagged and bounded to 24 h');
// 50 MB-style cap (small cap here)
$c5 = $ck($t5);
appendLog($app, spread($now - 140, $now - 100, 60, fn($ts, $i) => entry($ts, 'warning', 'app', 'Bulk entry ' . str_repeat('x', 60))));
$t6 = runScan($cpd, ["since=$since", 'max=2000', $c5]);
$fl = $t6->files['app.log']['flags'];
T::ok(count($fl) === 1 && str_starts_with($fl[0], 'capped:') && (int)substr($fl[0], 7) > 0, 'cap: flagged capped with skipped bytes');
T::ok(cnt($t6, 'Bulk entry') > 0 && cnt($t6, 'Bulk entry') < 60, 'cap: only the newest bytes read');
T::eq($t6->files['app.log']['offset'], (string)filesize($app), 'cap: checkpoint advanced to the end');
// unreadable / missing
$ud = tmpdir($WORK, 'cp-missing');
$t7 = runScan($ud, ["since=$since", 'max=1000']);
T::eq($t7->files['app.log']['flags'] ?? null, ['missing'], 'missing app.log reported, never "quiet"');

// truncate then grow past the old offset, same inode, different prefix
$gd = tmpdir($WORK, 'cp-grow');
$ga = "$gd/app.log";
file_put_contents($ga, str_repeat('A', 300) . "\n" . entry(kst($now - 80), 'warning', 'app', 'Grow original'));
$tg = runScan($gd, ["since=$since", 'max=52428800']);
$growIno = inodeOf($ga);
$cg = $ck($tg);
file_put_contents($ga, str_repeat('B', 400) . "\n" . entry(kst($now - 40), 'warning', 'app', 'Grow rewritten'));
T::eq(inodeOf($ga), $growIno, 'truncate-then-grow keeps the inode');
T::ok(filesize($ga) >= (int)$tg->files['app.log']['offset'], 'rewrite is at least the old checkpoint length');
$tg2 = runScan($gd, ["since=$since", 'max=52428800', $cg]);
T::eq($tg2->files['app.log']['flags'], ['truncated'], 'truncate-then-grow is flagged truncated');
T::eq(cnt($tg2, 'Grow rewritten'), 1, 'truncate-then-grow reads the new text');

// rotation hole: .2 present, .1 missing, current app.log present, plus a later file
$hd = tmpdir($WORK, 'cp-hole');
mkdir("$hd/cron", 0700);
$ha = "$hd/app.log";
file_put_contents($ha, entry(kst($now - 80), 'warning', 'app', 'Hole origin'));
$ht = runScan($hd, ["since=$since", 'max=52428800']);
appendLog($ha, entry(kst($now - 40), 'warning', 'app', 'Hole tail'));
rename($ha, "$hd/app.log.2");
file_put_contents($ha, entry(kst($now - 30), 'warning', 'app', 'Hole current'));
file_put_contents("$hd/cron/job.log", entry(kst($now - 20), 'warning', 'app', 'Hole cron'));
$hr = Fls\Proc::run(['/bin/bash', '-s', '--', 'role=service', "since=$since", 'max=52428800', "root=$hd", $ck($ht)], (string)file_get_contents(TOOL . '/payload/scan-v1.sh'), 60, null, ['TZ' => 'Asia/Seoul', 'PATH' => '/usr/bin:/bin', 'LC_ALL' => 'C']);
T::eq($hr['exit'], 0, 'a rotation hole does not abort the payload');
T::contains($hr['stdout'], "E\tscan-v1\tok", 'payload still emits a closing record after a hole');
$hp = Tsv::parse($hr['stdout']);
T::ok($hp->complete && in_array('hole', $hp->files['app.log']['flags'] ?? [], true), 'rotation hole is recorded on the F row');
T::eq(cnt($hp, 'Hole tail'), 1, 'unread tail of the segment before the hole is still scanned');
T::eq(cnt($hp, 'Hole current'), 1, 'current app.log is still scanned');
T::eq(cnt($hp, 'Hole cron'), 1, 'a later file is still scanned after a hole');

// decompressed gzip is capped, not only the compressed size
$zd = tmpdir($WORK, 'cp-gzcap');
file_put_contents("$zd/tmp.log", spread($now - 5000, $now - 4000, 30, fn($ts, $i) => entry($ts, 'warning', 'app', 'Gz bulk ' . str_repeat('y', 80))));
Fls\Proc::run(['/bin/sh', '-c', 'gzip -c tmp.log | cat > app.log.1.gz'], '', 10, $zd);
unlink("$zd/tmp.log");
file_put_contents("$zd/app.log", entry(kst($now - 30), 'warning', 'app', 'After gz cap'));
$zt = runScan($zd, ["since=$since", 'max=1500']);
T::ok($zt->complete, 'capped gzip scan completes');
T::eq(cnt($zt, 'After gz cap'), 1, 'plain file is still read when a gzip member is capped');
T::ok(cnt($zt, 'Gz bulk') > 0 && cnt($zt, 'Gz bulk') < 30, 'decompressed gzip output is capped');

// awk bearer / spaced password / ::1 / .uk (token is not printed)
$ad = tmpdir($WORK, 'awk-redact');
$ats = kst($now - 50);
$aline = static function (string $msg) use ($ats): string {
    return $ats . " [-][-][-][error][app] $msg\n";
};
file_put_contents("$ad/app.log", $aline("Authorization: Bearer $tok") . $aline("'HTTP_AUTHORIZATION' => 'Bearer $tok'") . $aline('password=zzWordOne zzWordTwo') . $aline('loopback ::1 host a.b.uk'));
$ar = Fls\Proc::run(['/bin/bash', '-s', '--', 'role=service', "since=$since", 'max=52428800', "root=$ad"], (string)file_get_contents(TOOL . '/payload/scan-v1.sh'), 60, null, ['TZ' => 'Asia/Seoul', 'PATH' => '/usr/bin:/bin', 'LC_ALL' => 'C']);
$groups = implode("\n", array_filter(explode("\n", $ar['stdout']), fn($l) => str_starts_with($l, 'G')));
T::ok(!str_contains($ar['stdout'], $tok), 'awk payload drops the bearer token');
T::ok(!str_contains($ar['stdout'], 'zzWordOne') && !str_contains($ar['stdout'], 'zzWordTwo'), 'awk payload drops a spaced password');
T::ok(!str_contains($groups, '::1') && !str_contains($groups, '.uk'), 'awk payload drops ::1 and a .uk host');
T::eq(Redact::tripwire($groups), null, 'tripwire quiet on awk-redacted groups');
T::eq(leakClasses($groups), [], 'leak oracle quiet on awk-redacted groups');

assertNoLeaks(implode("\n", array_map(fn($g) => $g['category'] . ' ' . $g['template'], array_merge($t->groups, $t2->groups, $t4->groups, $hp->groups))), 'payload groups');

// parent must not treat a rotation hole as a quiet success
$HF = tmpdir($WORK, 'hole-cli');
foreach (['service1', 'db'] as $role) {
    mkdir("$HF/fx/10010/$role", 0700, true);
    file_put_contents("$HF/fx/10010/$role/app.log", entry(kst(time() - 90), 'warning', 'app', 'Steady hole marker'));
}
$hcfg = writeConfig("$HF/config.php", []);
[$rc, $out, $err] = cli(['--daily', '--fixtures', "$HF/fx", '--config', $hcfg], [], $TRAP);
T::eq($rc, 0, 'hole fixture baseline exits 0');
rename("$HF/fx/10010/service1/app.log", "$HF/fx/10010/service1/app.log.2");
file_put_contents("$HF/fx/10010/service1/app.log", entry(kst(time() - 30), 'warning', 'app', 'Steady hole marker'));
[$rc, $out, $err] = cli(['--daily', '--fixtures', "$HF/fx", '--config', $hcfg], [], $TRAP);
T::eq($rc, 5, 'a rotation hole is a failed scan, not exit 0');
T::contains($out, 'rotation-hole', 'the digest names the rotation hole');
T::notContains($out, 'quiet (no new', 'a rotation hole is not the quiet line');

// ---------------------------------------------------------------- 4. pool (fake runner)
T::section('pool: cap, stagger, shared lane, timeout, breaker, no retries');
$plog = "$WORK/pool.log";
@unlink($plog);
$job = fn(string $id, string $lane, string $script) => ['id' => $id, 'lane' => $lane, 'argv' => ['/bin/sh', '-c', "echo $id >> '$plog'; $script"], 'stdin' => ''];
$cfgLanes = ['lanes' => ['jp' => ['jp'], 'sgv' => ['sg', 'vertex']]];
$jobs = [];
for ($i = 0; $i < 6; $i++) {
    $jobs[] = $job("sg$i", Config::laneOf($cfgLanes, 'sg'), 'sleep 0.6; echo H');
    $jobs[] = $job("vx$i", Config::laneOf($cfgLanes, 'vertex'), 'sleep 0.6; echo H');
}
$pool = new Pool(4, 0.15, 10);
$res = $pool->run($jobs);
T::eq(array_keys($pool->maxRunning), ['sgv'], 'SG and VERTEX share one lane');
T::ok($pool->maxRunning['sgv'] <= 4, 'cap: at most 4 concurrent on the shared lane (saw ' . $pool->maxRunning['sgv'] . ')');
$st = $pool->starts['sgv'];
$gaps = [];
for ($i = 1; $i < count($st); $i++) {
    $gaps[] = $st[$i] - $st[$i - 1];
}
T::ok(min($gaps) >= 0.149, sprintf('stagger: min gap %.3fs >= 0.15s', min($gaps)));
T::eq(count(array_filter($res, fn($r) => $r['status'] === 'ok')), 12, 'all 12 jobs ok');
@unlink($plog);
$pool = new Pool(4, 0.0, 1.0);
$res = $pool->run([$job('hang', 'jp', 'sleep 30'), $job('fast', 'jp', 'echo H')]);
T::eq([$res['hang']['status'], $res['fast']['status']], ['timeout', 'ok'], 'total timeout kills a hung session; others continue');
T::ok($res['hang']['duration'] < 3, 'timeout enforced near the limit');
@unlink($plog);
$pool = new Pool(1, 0.2, 10);
$res = $pool->run([
    $job('r1', 'jp', 'echo "kex: read: Connection reset by peer" 1>&2; exit 255'),
    $job('r2', 'jp', 'echo H'), $job('r3', 'jp', 'echo H'),
    $job('o1', 'sgv', 'echo H'),
]);
T::eq([$res['r1']['status'], $res['r2']['status'], $res['r3']['status'], $res['o1']['status']], ['reset', 'skipped-breaker', 'skipped-breaker', 'ok'], 'breaker: reset pauses that lane only; queued sessions skipped');
$calls = array_count_values(array_map('trim', file($plog)));
ksort($calls);
T::eq($calls, ['o1' => 1, 'r1' => 1], 'no retries: each session spawned at most once');
@unlink($plog);
$pool = new Pool(4, 0.0, 10);
$res = $pool->run([$job('hk', 'jp', 'echo "Host key verification failed." 1>&2; exit 255'), $job('pw', 'jp', "echo \"wwkker@x's password:\" 1>&2; exit 255"), $job('dn', 'jp', 'echo "Permission denied (publickey)." 1>&2; exit 255')]);
T::eq([$res['hk']['status'], $res['pw']['status'], $res['dn']['status']], ['hostkey', 'prompt', 'auth'], 'host-key / prompt / auth classified, not retried');
T::eq(array_sum(array_count_values(array_map('trim', file($plog)))), 3, 'three sessions, three spawns');

// ---------------------------------------------------------------- 5. site source + server list (fake global)
T::section('SiteSource / ServerList (fake global CLI, synthetic data)');
T::eq(SiteSource::parseSiteIds('[{"site_id":10010},{"id":"30030"},{"site_id":"abc"}]'), ['10010', '30030'], 'parses top-level list');
T::eq(SiteSource::parseSiteIds('{"data":{"items":[{"siteId":"11130"}]}}'), ['11130'], 'parses nested data/items');
T::eq(SiteSource::parseSiteIds("10010  ROZO  active\n  30030 X\nheader\n"), ['10010', '30030'], 'parses text fallback');
$sl = ServerList::fromGlobalOutput('{"data":[{"ip":"198.51.100.202","class":"S"},{"ip":"198.51.100.201","class":"S"},{"ip":"198.51.100.203","class":"DB"}]}');
T::eq(array_keys($sl->servers), ['service1', 'service2', 'db'], 'roles from classes, service ordinal by sorted address');
T::eq($sl->problem, null, 'service + db present');
T::eq(ServerList::fromGlobalOutput('[{"ip":"198.51.100.201","class":"S"}]')->problem, 'list unreadable', 'zero db -> list unreadable');
$ord = ServerList::fromGlobalOutput('{"data":[{"ip":"198.51.100.10","class":"S"},{"ip":"198.51.100.9","class":"S"},{"ip":"198.51.100.10","class":"DB"}]}');
T::ok(isset($ord->servers['service1'], $ord->servers['service2']) && str_ends_with($ord->servers['service1']['addr'], '.9') && str_ends_with($ord->servers['service2']['addr'], '.10'), 'numeric-aware order numbers the lower address first');
T::ok(isset($ord->servers['db']) && !isset($ord->servers['db1']), 'a single db stays unsuffixed');
$kept = ServerList::fromGlobalOutput('{"data":[{"id":20,"ip":"198.51.100.10","class":"S"},{"id":7,"ip":"198.51.100.11","class":"DB"}]}');
$added = ServerList::fromGlobalOutput('{"data":[{"id":20,"ip":"198.51.100.10","class":"S"},{"id":1,"ip":"198.51.100.9","class":"S"},{"id":7,"ip":"198.51.100.11","class":"DB"},{"id":8,"ip":"198.51.100.8","class":"DB"}]}');
T::ok(isset($kept->servers['service20'], $added->servers['service20']) && $kept->servers['service20']['addr'] === $added->servers['service20']['addr'], 'adding a lower-sorting address keeps the previous service role');
T::ok(isset($added->servers['db7']) && !isset($added->servers['db1']) && $kept->servers['db7']['addr'] === $added->servers['db7']['addr'], 'a second db does not take the first db checkpoint key');
$cfgOk = Config::load(TOOL . '/config.php', TOOL);
T::eq(Config::laneOf($cfgOk, 'sg'), Config::laneOf($cfgOk, 'vertex'), 'default config: sg and vertex share a lane');
$split = $cfgOk;
$split['lanes'] = ['jp' => ['jp'], 'sgv' => ['sg'], 'vx' => ['vertex']];
try {
    Config::validate($split);
    T::ok(false, 'lanes that split sg and vertex are refused');
} catch (Fls\FlsException $e) {
    T::contains($e->getMessage(), 'share one lane', 'lanes that split sg and vertex are refused');
}

// ---------------------------------------------------------------- 6. fleet fixtures, daily runs over 5 days (+ webhook listener)
T::section('fleet fixtures: daily runs, baseline, quiet day, must-flag, known-harmless, webhook');
$FL = tmpdir($WORK, 'fleet');
$FX = "$FL/fixtures";
$roles = ['10010' => ['service1', 'service2', 'db'], '30030' => ['service1', 'service2', 'admin', 'db'], '11130' => ['service1', 'admin', 'db']];
foreach ($roles as $s => $rs) {
    foreach ($rs as $role) {
        mkdir("$FX/$s/$role", 0700, true);
    }
}
$D5 = time() - 3600;
$nowOf = fn(int $k) => $D5 - (5 - $k) * 86400;
function fleetDay(string $FX, int $k, int $from, int $to, array $roles): void
{
    foreach ($roles as $s => $rs) {
        $s = (string)$s;
        foreach ($rs as $role) {
            $f = "$FX/$s/$role/app.log";
            $d = '';
            if (str_starts_with($role, 'service') && !($s === '10010' && $role === 'service1' && $k === 5)) {
                $d .= spread($from, $to, 5, fn($ts) => entry($ts, 'warning', 'yii\web\HttpException:400', 'Unable to verify your data submission.'));
                $d .= spread($from, $to, 3, fn($ts) => entry($ts, 'error', 'yii\web\HttpException:404', 'Unable to resolve the request "wp-login.php".'));
            }
            if ($s === '10010' && str_starts_with($role, 'service') && !($role === 'service1' && $k === 5)) {
                $d .= spread($from, $to, 10, fn($ts, $i) => entry($ts, 'warning', 'application', 'Order validation failed for order ' . (1000 + $i) . ' amount ' . (50 * $i)));
            }
            if ($s === '30030' && $role === 'service1') {
                $d .= spread($from, $to, 4, fn($ts) => cookieDump($ts));
                $d .= spread($from, $to, 6, fn($ts) => entry($ts, 'error', 'app\components\PaymentCallback', 'Payment callback failed for player@example.com from 198.51.100.23 token=FAKEtoken0123456789abcdefXYZ phone 09175550199 Authorization: Bearer FAKEtoken0123456789abcdefXYZ', ['Stack trace:', '#0 /var/www/domain-0/components/PaymentCallback.php(88): run()', '#1 {main}']));
                $d .= rtrim(entry(kst($to - 50), 'warning', 'app', 'First of a concatenated pair'), "\n") . entry(kst($to - 49), 'warning', 'app', 'Second of a concatenated pair');
            }
            if ($s === '30030' && $role === 'service2' && $k === 5) {
                $d .= spread($from, $to, 4, fn($ts) => entry($ts, 'error', 'yii\base\InvalidRouteException', 'Unable to resolve the request "telescope/requests".'));
            }
            if ($role === 'admin') {
                $n = $s === '30030' ? ($k === 5 ? 88 : 26) : 10;
                $d .= spread($from, $to, $n, fn($ts) => entry($ts, 'warning', 'application', 'Casino branch money is unavailable in /var/www/domain-0/common/ConstCasinoSlot.php:836'));
            }
            if ($s === '10010' && $role === 'db') {
                $d .= spread($from, $to, $k === 5 ? 35 : 30, fn($ts, $i) => entry($ts, 'warning', 'app\controllers\SocketSiteSportsController::_decodeJson', 'Sports socket JSON decode failed: context=client-data len=' . (100 + $i)));
                if ($k === 4) {
                    file_put_contents($f, '');
                }
            }
            if ($s === '30030' && $role === 'db') {
                $d .= spread($from, $to, 8, fn($ts) => entry($ts, 'warning', 'application', 'Casino callback signature mismatch for provider evo'));
                if ($k === 3) {
                    rename($f, "$FX/$s/$role/app.log.1");
                }
            }
            if ($s === '11130' && $role === 'db') {
                $d .= spread($from, $to, 4, fn($ts) => entry($ts, 'warning', 'application', 'statsLog heartbeat late'));
                if ($k === 5) {
                    $d .= spread($from, $to, 171, fn($ts) => entry($ts, 'error', 'yii\db\Exception', 'Fork child failed in /var/www/domain-0/console/controllers/BaseProcessController.php:305', ['Stack trace:', '#0 /var/www/domain-0/console/controllers/BaseProcessController.php(305): fork()']));
                }
            }
            if ($s === '11130' && $role === 'service1' && $k === 1) {
                file_put_contents("$FX/$s/$role/app.log.1", spread($from, $from + 3600, 5, fn($ts) => entry($ts, 'warning', 'app', 'Legacy rotated entry')));
            }
            appendLog($f, $d);
        }
    }
}
[$lp, $port] = startListener($FL);
$cfgFile = writeConfig("$FL/config.php", ['sites' => ['include' => [], 'exclude' => []]]);
$DATA = "$FL/data";
writeWebhookEnv("$FL/webhook.env", "http://127.0.0.1:$port/fleet-scan");
$stdoutAll = '';
for ($k = 1; $k <= 4; $k++) {
    fleetDay($FX, $k, $nowOf($k) - 86400, $nowOf($k) - 60, $roles);
    $extra = $k === 4 ? ['--webhook-always'] : [];
    [$rc, $out, $err] = cli(['--daily', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)$nowOf($k), ...$extra], [], $TRAP);
    $stdoutAll .= $out . $err;
    T::eq($rc, 0, "day $k exit 0");
    $caps = captures($FL);
    if ($k === 1) {
        T::contains($out, 'baseline', 'day 1: baseline summary, not alerts');
        T::ok(!preg_match('/NEW |\dx /', $out), 'day 1: no NEW/spike alert lines');
        T::eq(count($caps), 1, 'day 1: webhook posted once (baseline is a change)');
        $b = json_decode($caps[0]['body'] ?? '{}', true);
        T::eq([$b['schema'] ?? null, $b['changed'] ?? null, $b['items'] ?? null], ['fleet-log-scan.webhook.v1', true, []], 'day 1: webhook shape (schema, changed, no items)');
        T::eq($caps[0]['auth'] ?? null, 'Bearer whsecret-FAKE-0123456789', 'webhook carries the auth header to the listener');
        T::eq(count(glob("$DATA/outbox/*.json")), 1, 'day 1: digest queued in outbox (pending-not-fired)');
        T::contains((string)file_get_contents(glob("$DATA/outbox/*.json")[0]), 'pending-not-fired', 'delivery hook not fired');
    } elseif ($k < 4) {
        T::contains($out, 'quiet', "day $k: quiet day message on stdout only");
        T::eq(count($caps), 0, "day $k: quiet day -> no webhook");
        T::eq(count(glob("$DATA/outbox/*.json")), 1, "day $k: quiet day -> no digest queued");
    } else {
        T::contains($out, 'quiet', 'day 4: quiet');
        T::eq(count($caps), 1, 'day 4: --webhook-always posts on a quiet day');
        $b = json_decode($caps[0]['body'] ?? '{}', true);
        T::eq([$b['changed'] ?? null, $b['severity'] ?? null], [false, 'info'], 'day 4: webhook says unchanged, info');
    }
    clearCaptures($FL);
    // checkpoints advance to file size for every role
    $okCp = true;
    foreach ($roles as $s => $rs) {
        $cp = Fs::readJson("$DATA/state/checkpoints/$s.json");
        foreach ($rs as $role) {
            clearstatcache();
            $okCp = $okCp && ($cp[$role]['app.log']['offset'] ?? null) === (string)filesize("$FX/$s/$role/app.log")
                && ($cp[$role]['app.log']['inode'] ?? null) === (string)fileinode("$FX/$s/$role/app.log");
        }
    }
    T::ok($okCp, "day $k: checkpoints = current inode + size for every server");
}
$rep3 = (string)file_get_contents(glob("$DATA/reports/*.txt")[2] ?? '/dev/null');
$rep4 = implode("\n", array_map('file_get_contents', glob("$DATA/reports/*.txt")));
T::contains($rep4, '10010 db app.log was truncated', 'truncation noted in the report');
// day 5: dry-run first (no POST, no state change), then the real run
fleetDay($FX, 5, $nowOf(5) - 86400, $nowOf(5) - 60, $roles);
$stateHash = fn() => md5(implode('', array_map(fn($f) => $f . file_get_contents($f), array_filter(array_merge(glob("$DATA/state/*.json"), glob("$DATA/state/*/*.json")), 'is_file'))));
$before = $stateHash();
[$rc, $out, $err] = cli(['--daily', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)$nowOf(5), '--dry-run', '--webhook-dry-run'], [], $TRAP);
T::eq(count(captures($FL)), 0, 'day 5 --dry-run/--webhook-dry-run: nothing POSTed');
T::contains($out, '"schema": "fleet-log-scan.webhook.v1"', 'webhook dry-run prints the payload');
T::eq($stateHash(), $before, 'dry-run leaves state unchanged');
$stdoutAll .= $out . $err;
[$rc, $out, $err] = cli(['--daily', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)$nowOf(5)], [], $TRAP);
$stdoutAll .= $out . $err;
T::eq($rc, 0, 'day 5 exit 0');
T::ok((bool)preg_match('/11130 db\s+NEW error \(fatal\/error\/5xx\)\s+yii\\\\db\\\\Exception "Fork child failed in BaseProcessController\.php:305"\s+171/', $out), 'must-flag: 11130 db NEW fatal "Fork child failed" 171');
T::ok((bool)preg_match('/30030 admin\s+3\.4x\s+warning application "Casino branch money is unavailable in ConstCasinoSlot\.php:836"\s+88 \(usual 26\)/', $out), 'must-flag: 30030 admin Casino branch money 3.4x, 88 (usual 26)');
T::contains($out, '10010 service1 possibly out of rotation', 'stale: 10010 service1 possibly out of rotation');
T::notContains($out, 'telescope', 'known-harmless: new scanner 404 route stays quiet');
T::notContains($out, 'Sports socket', 'known-harmless: sports socket partial-frame stays quiet (1.2x)');
T::notContains($out, 'Unable to verify', 'known-harmless: CSRF 400 stays quiet');
T::contains($out, 'Limits: wwkker cannot read /var/log/apache2', 'digest footer states the limits');
$caps = captures($FL);
T::eq(count($caps), 1, 'day 5: webhook posted exactly once');
$b = json_decode($caps[0]['body'] ?? '{}', true);
$flagsSeen = array_map(fn($i) => $i['site'] . ' ' . $i['role'] . ' ' . $i['flag'], $b['items'] ?? []);
sort($flagsSeen);
T::eq($flagsSeen, ['11130 db new-fatal', '30030 admin spike'], 'webhook items = the two must-flags');
T::eq($b['severity'] ?? null, 'critical', 'webhook severity critical on a new fatal');
T::eq(array_keys($b), ['schema', 'run_id', 'mode', 'generated_at', 'severity', 'changed', 'baseline_sites', 'servers', 'items', 'failures', 'notes', 'summary', 'summary_status', 'dropped_by_tripwire', 'payload_versions'], 'webhook payload keys');
assertNoLeaks($caps[0]['body'] ?? '', 'webhook body');
clearCaptures($FL);
$h11 = Fs::readJson("$DATA/state/groups/11130.json");
$fork = array_values(array_filter($h11['groups'], fn($g) => str_contains($g['template'], 'Fork child')))[0] ?? [];
T::eq(array_sum(array_column($fork['days'] ?? [], 'count')), 171, 'counts match: Fork child failed = 171');
$h30 = Fs::readJson("$DATA/state/groups/30030.json");
$cas = array_values(array_filter($h30['groups'], fn($g) => str_contains($g['template'], 'Casino branch') && $g['role'] === 'admin'))[0] ?? [];
T::eq(array_values(array_column($cas['days'] ?? [], 'count')), [26, 26, 26, 26, 88], 'counts match: casino branch per day');
$pay = array_values(array_filter($h30['groups'], fn($g) => str_contains($g['template'], 'Payment callback')))[0] ?? [];
T::eq(array_sum(array_column($pay['days'] ?? [], 'count')), 30, 'counts match: payment callback 6/day x5 (cookie dumps not counted)');
T::ok(!array_filter($h30['groups'], fn($g) => str_contains($g['template'], 'COOKIE')), '$_COOKIE/$_SERVER info dumps not counted');
// --site / --region on fixtures
[$rc, $out, $err] = cli(['--site', '30030', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 120)], [], $TRAP);
T::contains($out, 'groups', '--site prints a table to the terminal');
T::ok(!str_contains($out, '10010') && !str_contains($out, '11130'), '--site limits to one site');
[$rc, $out, $err] = cli(['--region', 'sg', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 240)], [], $TRAP);
T::ok(str_contains($out, '11130') && !str_contains($out, '30030') && !str_contains($out, '10010'), '--region sg limits to 11xxx sites');
$stdoutAll .= $out . $err;
assertNoLeaks(allOutput($DATA, [$stdoutAll]), 'fleet runs (stdout/stderr, reports, state, outbox)');
T::notContains(allOutput($DATA, [$stdoutAll]), 'whsecret', 'webhook secret never in stdout/stderr/reports/state');
T::eq(permsOk($DATA), [], 'all data dirs 0700 and files 0600');
T::eq(glob("$DATA/scratch/*") ?: [], [], 'scratch removed after runs');

// webhook failure modes
T::section('webhook failure modes (local only)');
writeWebhookEnv("$FL/webhook.env", 'http://127.0.0.1:' . ($port + 1 === 65536 ? 1 : 9) . '/closed');
[$rc, $out, $err] = cli(['--site', '30030', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 400), '--webhook-always'], [], $TRAP);
T::eq($rc, 0, 'closed port: run does not crash');
T::contains($out, 'webhook delivery error: connection failed', 'closed port: reported delivery error');
writeWebhookEnv("$FL/webhook.env", "http://127.0.0.1:$port/slow", "WEBHOOK_TIMEOUT=2\n");
$ts = microtime(true);
[$rc, $out, $err] = cli(['--site', '30030', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 500), '--webhook-always'], [], $TRAP);
T::contains($out, 'webhook delivery error', 'slow endpoint: timeout reported');
T::ok(microtime(true) - $ts < 30, 'slow endpoint: bounded by timeout');
sleep(1);
T::eq(count(captures($FL)), 1, 'slow endpoint: exactly one attempt (no retries)');
clearCaptures($FL);
writeWebhookEnv("$FL/webhook.env", "http://127.0.0.1:$port/fail");
[$rc, $out, $err] = cli(['--site', '30030', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 600), '--webhook-always'], [], $TRAP);
T::contains($out, 'webhook delivery error: HTTP 500', 'HTTP 500 reported');
clearCaptures($FL);
writeWebhookEnv("$FL/webhook.env", 'https://hooks.example.invalid/x');
[$rc, $out, $err] = cli(['--site', '30030', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 700), '--webhook-always'], [], $TRAP);
T::contains((string)file_get_contents("$DATA/state/last-run.json"), 'only posts to a loopback URL', 'non-loopback URL never contacted in fixtures mode');
unlink("$FL/webhook.env");
[$rc, $out, $err] = cli(['--site', '30030', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 800), '--webhook-always'], [], $TRAP);
T::contains((string)file_get_contents("$DATA/state/last-run.json"), 'webhook.env missing', 'no webhook.env -> disabled');
writeWebhookEnv("$FL/webhook.env", "http://127.0.0.1:$port/x");
chmod("$FL/webhook.env", 0644);
[$rc, $out, $err] = cli(['--site', '30030', '--fixtures', $FX, '--config', $cfgFile, '--now', (string)($nowOf(5) + 900), '--webhook-always'], [], $TRAP);
T::contains((string)file_get_contents("$DATA/state/last-run.json"), 'permissions too open', 'webhook.env 0644 -> disabled');
T::eq(count(captures($FL)), 0, 'nothing posted when disabled');
$w = Webhook::fromEnvFile("$FL/webhook.env");
chmod("$FL/webhook.env", 0600);
$w = Webhook::fromEnvFile("$FL/webhook.env");
T::eq($w->mask("POST http://127.0.0.1:$port/x Authorization: Bearer whsecret-FAKE-0123456789"), 'POST <webhook-redacted> Authorization <webhook-redacted>', 'mask hides URL and auth in debug text');
T::notContains(allOutput($DATA, [$out, $err]), 'whsecret', 'webhook secret never stored');
proc_terminate($lp);

// ---------------------------------------------------------------- 7. live code path with stubs only (fake ssh + fake global)
T::section('live code path with fake ssh + fake global (no network)');
$LV = tmpdir($WORK, 'live');
$addrs = [
    '10010' => ['service1' => '198.51.100.201', 'service2' => '198.51.100.202', 'db' => '198.51.100.203'],
    '30030' => ['service1' => '198.51.100.204', 'service2' => '203.0.113.205', 'admin' => '203.0.113.206', 'db' => '203.0.113.207'],
    '11130' => ['service1' => '203.0.113.208', 'admin' => '192.0.2.209', 'db' => '192.0.2.210'],
];
$class = fn($r) => match (true) { str_starts_with($r, 'service') => 'S', $r === 'admin' => 'A', default => 'DB' };
$g = ['sites' => ['jp' => ['data' => [['site_id' => 10010], ['site_id' => 99999]]], 'sg' => [['id' => '11130']], 'vertex' => ['sites' => [['site_id' => '30030']]]], 'servers' => []];
$map = [];
foreach ($addrs as $s => $rs) {
    foreach ($rs as $role => $a) {
        $g['servers'][$s]['data'][] = ['id' => count($map) + 1, 'ip' => $a, 'class' => $class($role)];
        $map[$a] = ['dir' => "$FX/$s/$role", 'mode' => 'ok'];
    }
}
file_put_contents("$LV/global.json", json_encode($g));
$writeMap = fn(array $m) => file_put_contents("$LV/sshmap.json", json_encode($m));
$writeMap($map);
$env = ['FLS_FAKE_SSH_MAP' => "$LV/sshmap.json", 'FLS_FAKE_SSH_LOG' => "$LV/ssh-argv.log", 'FLS_FAKE_GLOBAL' => "$LV/global.json", 'FLS_FAKE_GLOBAL_LOG' => "$LV/global-argv.log"];
$liveCfg = ['live' => ['enabled' => true], 'ssh_bin' => "$STUBS/fake-ssh.php", 'global_cli' => ['enabled' => true, 'bin' => "$STUBS/fake-global.php"]];
$cfgL = writeConfig("$LV/config.php", $liveCfg);
$ts = microtime(true);
[$rc, $out, $err] = cli(['--region', 'jp', '--config', $cfgL], $env, $TRAP);
$liveOut = $out . $err;
T::eq($rc, 0, 'live --region jp via stubs exit 0');
T::contains($out, '10010', 'site discovered through (fake) global');
T::notContains($out, '99999', 'unknown region prefix filtered');
$sshArgv = array_map(fn($l) => json_decode($l, true), file("$LV/ssh-argv.log", FILE_IGNORE_NEW_LINES));
T::eq(count($sshArgv), 3, 'one session per 10010 server');
T::eq(array_slice($sshArgv[0], 0, 9), ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '-o', 'ConnectionAttempts=1', '-o', 'ForwardAgent=no', 'rti-jump-jp'], 'outer ssh: BatchMode, ConnectTimeout 15, one attempt, no agent, jump alias');
T::ok((bool)preg_match('/^ssh -o BatchMode=yes -o ConnectTimeout=15 -o ConnectionAttempts=1 -o ForwardAgent=no wwkker@[0-9.]+ "bash -s -- role=(service|db) since=\d+ max=52428800( ck=[^ "]+)*"$/', $sshArgv[0][9]), 'inner ssh: user wwkker, bash -s -- validated args, no root=');
$st = []; // stagger check from start times not exposed; check wall time >= 2 * 2.5s for 3 sessions
T::ok(microtime(true) - $ts >= 5.0, 'config stagger (2.5 s) applied on the live path');
$gargv = file_get_contents("$LV/global-argv.log");
T::contains($gargv, '"site","list"', 'global site list called');
T::notContains($gargv, 'deploy', 'only read-only global subcommands used');
foreach (['--yes', 'create', 'update', 'delete', 'enable', 'disable', 'add', 'set-'] as $w) {
    T::notContains($gargv, '"' . $w, "no mutating global flag/subcommand ($w)");
}
[$rc, $out, $err] = cli(['--site', '30030', '--config', $cfgL], $env, $TRAP);
$liveOut .= $out . $err;
T::eq($rc, 0, 'live --site 30030 via stubs');
// breaker on the shared SG+VERTEX lane: first job (11130 service1) resets
$m2 = $map;
$m2[$addrs['11130']['service1']]['mode'] = 'reset';
$writeMap($m2);
@unlink("$LV/ssh-argv.log");
$cfgL2 = writeConfig("$LV/config2.php", $liveCfg + ['data_dir' => "$LV/data2"]);
[$rc, $out, $err] = cli(['--daily', '--config', $cfgL2], $env, $TRAP);
$liveOut .= $out . $err;
T::eq($rc, 5, 'breaker run exits 5 (scan failures are never silent)');
T::contains($out, 'circuit breaker tripped on lane sgv', 'breaker reported');
T::ok((bool)preg_match('/11130 service\d+ FAILED reset/', $out), 'reset server reported');
T::contains($out, 'FAILED skipped-breaker', 'queued sessions on the lane skipped');
$calls = count(file("$LV/ssh-argv.log"));
T::eq($calls, 4, 'no retries: 3 jp sessions + 1 sgv session (then paused)');
// tripwire end to end: a server returns a leaking row
$m3 = $map;
$m3[$addrs['10010']['db']]['mode'] = 'leak';
$writeMap($m3);
$cfgL3 = writeConfig("$LV/config3.php", $liveCfg + ['data_dir' => "$LV/data3"]);
[$rc, $out, $err] = cli(['--site', '10010', '--config', $cfgL3], $env, $TRAP);
$liveOut .= $out . $err;
T::contains($out, 'redaction-tripwire', 'tripwire fires on a planted leak and is reported');
T::notContains($out, 'leaked raw', 'leaking row not shown');
T::notContains(allOutput("$LV/data3"), 'leaked raw', 'leaking row not stored');
// global missing -> include list fallback; exclude wins
$writeMap($map);
$cfgL4 = writeConfig("$LV/config4.php", ['live' => ['enabled' => true], 'ssh_bin' => "$STUBS/fake-ssh.php", 'global_cli' => ['enabled' => true, 'bin' => '/nonexistent/global'], 'data_dir' => "$LV/data4", 'sites' => ['include' => ['10010', '11130'], 'exclude' => ['11130']]]);
[$rc, $out, $err] = cli(['--daily', '--config', $cfgL4], $env, $TRAP);
$liveOut .= $out . $err;
T::contains($out, 'global CLI missing; used config include list', 'global missing -> fallback reported in the digest');
T::ok(str_contains($out, '10010') && !preg_match('/^11130 /m', $out), 'include adds, exclude wins');
$gs = $g;
$gs['fail'] = ['jp', 'sg', 'vertex'];
file_put_contents("$LV/global-fail.json", json_encode($gs));
$cfgL5 = writeConfig("$LV/config5.php", $liveCfg + ['data_dir' => "$LV/data5", 'sites' => ['include' => ['10010'], 'exclude' => []]]);
[$rc, $out, $err] = cli(['--daily', '--config', $cfgL5], ['FLS_FAKE_GLOBAL' => "$LV/global-fail.json"] + $env, $TRAP);
$liveOut .= $out . $err;
T::contains($out, 'global CLI gave no usable list', 'global errors -> fallback reported');
T::notContains($out, 'ga.example.invalid', 'global stderr (URLs) never echoed');
assertNoLeaks(allOutput("$LV/data", [$liveOut]) . allOutput("$LV/data2") . allOutput("$LV/data3") . allOutput("$LV/data4") . allOutput("$LV/data5"), 'live-path outputs (fake addresses)');

// stable role keeps its checkpoint when a lower-sorting peer is added
$CK = tmpdir($WORK, 'ckpt-stable');
$oldDir = "$CK/old";
$newDir = "$CK/new";
$dbDir = "$CK/db";
mkdir($oldDir, 0700);
mkdir($newDir, 0700);
mkdir($dbDir, 0700);
file_put_contents("$oldDir/app.log", entry(kst(time() - 120), 'warning', 'app', 'Stable role marker'));
file_put_contents("$newDir/app.log", entry(kst(time() - 120), 'warning', 'app', 'New peer marker'));
file_put_contents("$dbDir/app.log", entry(kst(time() - 120), 'warning', 'app', 'Stable db marker'));
$addrOld = '198.51.100.50';
$addrNew = '198.51.100.9';
$addrDb = '198.51.100.51';
$gk = static function (array $rows) {
    return ['sites' => ['jp' => ['data' => [['site_id' => '10010']]], 'sg' => ['data' => [['site_id' => '11130']]], 'vertex' => ['data' => [['site_id' => '30030']]]], 'servers' => ['10010' => ['data' => $rows]]];
};
file_put_contents("$CK/global.json", json_encode($gk([
    ['id' => 20, 'ip' => $addrOld, 'class' => 'service'],
    ['id' => 7, 'ip' => $addrDb, 'class' => 'db'],
])));
$cmap = [$addrOld => ['dir' => $oldDir, 'mode' => 'ok'], $addrDb => ['dir' => $dbDir, 'mode' => 'ok']];
file_put_contents("$CK/sshmap.json", json_encode($cmap));
$ckEnv = ['FLS_FAKE_SSH_MAP' => "$CK/sshmap.json", 'FLS_FAKE_SSH_LOG' => "$CK/ssh.log", 'FLS_FAKE_GLOBAL' => "$CK/global.json", 'FLS_FAKE_GLOBAL_LOG' => "$CK/global.log"];
$ckCfg = writeConfig("$CK/config.php", ['live' => ['enabled' => true], 'ssh_bin' => "$STUBS/fake-ssh.php", 'global_cli' => ['enabled' => true, 'bin' => "$STUBS/fake-global.php"], 'data_dir' => "$CK/data"]);
[$rc, $out, $err] = cli(['--site', '10010', '--config', $ckCfg], $ckEnv, $TRAP);
T::eq($rc, 0, 'stable-role first scan exits 0');
$cp1 = json_decode((string)file_get_contents("$CK/data/state/checkpoints/10010.json"), true);
T::eq($cp1['service20']['app.log']['inode'] ?? '', inodeOf("$oldDir/app.log"), 'first scan checkpoints the original service role');
file_put_contents("$CK/global.json", json_encode($gk([
    ['id' => 20, 'ip' => $addrOld, 'class' => 'service'],
    ['id' => 1, 'ip' => $addrNew, 'class' => 'service'],
    ['id' => 7, 'ip' => $addrDb, 'class' => 'db'],
])));
$cmap[$addrNew] = ['dir' => $newDir, 'mode' => 'ok'];
file_put_contents("$CK/sshmap.json", json_encode($cmap));
[$rc, $out, $err] = cli(['--site', '10010', '--config', $ckCfg], $ckEnv, $TRAP);
T::eq($rc, 0, 'stable-role second scan exits 0');
$cp2 = json_decode((string)file_get_contents("$CK/data/state/checkpoints/10010.json"), true);
T::eq($cp2['service20']['app.log']['inode'] ?? '', inodeOf("$oldDir/app.log"), 'previous server keeps its checkpoint after a lower address is added');
T::eq($cp2['service1']['app.log']['inode'] ?? '', inodeOf("$newDir/app.log"), 'the new server gets its own checkpoint');
T::ok(!str_contains(json_encode($cp2), $addrOld) && !str_contains(json_encode($cp2), $addrNew), 'checkpoint file does not store addresses');

// a partial global list is not a quiet fleet
$PT = tmpdir($WORK, 'partial');
$sites = ['10010' => 'jp', '11130' => 'sg', '30030' => 'vertex'];
$prows = [];
$pmap = [];
$i = 0;
foreach ($sites as $site => $profile) {
    foreach (['service', 'db'] as $cls) {
        $i++;
        $dir = "$PT/logs/$site/$cls";
        mkdir($dir, 0700, true);
        file_put_contents("$dir/app.log", entry(kst(time() - 180), 'warning', 'app', 'Partial steady marker'));
        $addr = $cls === 'service' ? "198.51.100.21$i" : "198.51.100.22$i";
        $prows[$site][] = ['id' => $i, 'ip' => $addr, 'class' => $cls];
        $pmap[$addr] = ['dir' => $dir, 'mode' => 'ok'];
    }
}
$pg = ['sites' => [], 'servers' => []];
foreach ($sites as $site => $profile) {
    $pg['sites'][$profile] = ['data' => [['site_id' => $site]]];
    $pg['servers'][$site] = ['data' => $prows[$site]];
}
file_put_contents("$PT/global.json", json_encode($pg));
file_put_contents("$PT/sshmap.json", json_encode($pmap));
$pEnv = ['FLS_FAKE_SSH_MAP' => "$PT/sshmap.json", 'FLS_FAKE_SSH_LOG' => "$PT/ssh.log", 'FLS_FAKE_GLOBAL' => "$PT/global.json", 'FLS_FAKE_GLOBAL_LOG' => "$PT/global.log"];
$pCfg = writeConfig("$PT/config.php", ['live' => ['enabled' => true], 'ssh_bin' => "$STUBS/fake-ssh.php", 'global_cli' => ['enabled' => true, 'bin' => "$STUBS/fake-global.php"], 'data_dir' => "$PT/data"]);
[$rc, $out, $err] = cli(['--daily', '--config', $pCfg], $pEnv, $TRAP);
T::eq($rc, 0, 'partial-list baseline exits 0');
T::notContains($out, 'quiet (no new', 'first live day is a baseline, not the quiet line');
[$rc, $out, $err] = cli(['--daily', '--config', $pCfg], $pEnv, $TRAP);
T::eq($rc, 0, 'complete site list can finish quietly');
T::contains($out, 'quiet (no new', 'complete site list prints the quiet line');
$pg['sites']['vertex'] = ['data' => []];
file_put_contents("$PT/global.json", json_encode($pg));
[$rc, $out, $err] = cli(['--daily', '--config', $pCfg], $pEnv, $TRAP);
T::eq($rc, 5, 'partial site list exits 5');
T::contains($out, 'partial', 'partial site list is reported');
T::notContains($out, 'quiet (no new', 'partial site list is not a quiet fleet');
assertNoLeaks($out . $err . allOutput("$PT/data") . allOutput("$CK/data"), 'partial and checkpoint outputs');

// ---------------------------------------------------------------- 8. model summary (stubbed cursor-agent)
T::section('optional summary via cursor-agent stub (grok-4.7-xhigh-fast only)');
$SM = tmpdir($WORK, 'summary');
$sfx = "$SM/fx";
mkdir("$sfx/11130/db", 0700, true);
mkdir("$sfx/11130/service1", 0700, true);
file_put_contents("$sfx/11130/db/app.log", spread(time() - 7200, time() - 100, 5, fn($ts) => entry($ts, 'error', 'yii\db\Exception', 'Fork child failed for player@example.com from 198.51.100.23')));
file_put_contents("$sfx/11130/service1/app.log", spread(time() - 7200, time() - 100, 2, fn($ts) => entry($ts, 'warning', 'app', 'x')));
$cap = "$SM/capture.jsonl";
$ws = getenv('HOME') . '/.openclaw/workspace-abella';
$cfgS = writeConfig("$SM/config.php", ['model' => ['enabled' => true, 'name' => 'grok-4.7-xhigh-fast', 'bin' => "$STUBS/fake-cursor-agent.php", 'cwd' => $ws]]);
[$rc, $out, $err] = cli(['--daily', '--fixtures', $sfx, '--config', $cfgS], ['FLS_STUB_CAPTURE' => $cap], $TRAP);
$c = json_decode((string)(file($cap)[0] ?? 'null'), true);
$i = array_search('--model', $c['argv'] ?? [], true);
T::ok($i !== false && ($c['argv'][$i + 1] ?? '') === 'grok-4.7-xhigh-fast', 'argv includes --model grok-4.7-xhigh-fast');
$sumCwd = (string)($c['cwd'] ?? '');
T::ok($sumCwd !== '' && !str_contains($sumCwd, 'fleet-log-scan') && !str_contains($sumCwd, 'workspace-abella'), 'summary cwd is an isolated temp dir');
T::eq($c['cwd_entries'] ?? -1, 0, 'summary cwd is empty');
T::ok(!is_dir($sumCwd), 'summary temp dir is removed');
T::ok(!in_array('auto', $c['argv'] ?? [], true) && in_array('ask', $c['argv'] ?? [], true) && !array_intersect(['--force', '-f', '--trust', '--yolo'], $c['argv'] ?? []), 'argv: --mode ask, never auto/--force/--trust/--yolo');
$input = implode(' ', $c['argv'] ?? []) . ($c['stdin'] ?? '');
T::eq(Redact::tripwire(str_replace('grok-4.7-xhigh-fast', '', $input)), null, 'model input has no redaction-class strings');
assertNoLeaks($input, 'model input');
T::contains($out, 'Summary (grok-4.7-xhigh-fast):', 'summary appended to the digest');
Fs::rmTree("$SM/data");
writeConfig("$SM/config.php", ['model' => ['enabled' => true, 'name' => 'grok-4.7-xhigh-fast', 'bin' => "$STUBS/fake-cursor-agent.php", 'cwd' => $SM]]);
[$rc, $out, $err] = cli(['--daily', '--fixtures', $sfx, '--config', $cfgS], ['FLS_STUB_CAPTURE' => $cap, 'FLS_STUB_MODE' => 'fail'], $TRAP);
T::contains($out, 'summary skipped: model unavailable', 'model failure -> "summary skipped: model unavailable"');
$cFail = json_decode((string)(file($cap)[1] ?? 'null'), true);
T::ok(!is_dir((string)($cFail['cwd'] ?? '')), 'a failed summary still removes its temp dir');
T::contains($out, 'Fleet scan', 'digest still complete without a summary');
T::eq(count(file($cap)), 2, 'one call per run, no retry or other model');
foreach (['auto', 'grok-4.7-high', 'claude-opus-5-5'] as $bad) {
    $cfgB = writeConfig("$SM/config-bad.php", ['model' => ['enabled' => true, 'name' => $bad]]);
    [$rc, $out, $err] = cli(['--daily', '--fixtures', $sfx, '--config', $cfgB], [], $TRAP);
    T::ok($rc === 2 && str_contains($err, 'model.name must be exactly grok-4.7-xhigh-fast'), "config rejects model name '$bad'");
}
$argv = Summary::argv(Config::load($cfgS, TOOL), 'p');
T::eq(array_slice($argv, 1, 5), ['-p', '--model', 'grok-4.7-xhigh-fast', '--mode', 'ask'], 'Summary::argv exact');

// ---------------------------------------------------------------- 9. trace mode on fixtures
T::section('trace mode (fixtures only)');
$TR = tmpdir($WORK, 'trace');
$tf = "$TR/fx/10010";
foreach (['service1', 'admin', 'db'] as $r) {
    mkdir("$tf/$r", 0700, true);
}
$RID1 = '11111111-2222-4333-8444-555555555555';
$RID2 = '22222222-3333-4444-8555-666666666666';
$RID3 = '33333333-4444-4555-8666-777777777777';
$RID4 = '44444444-5555-4666-8777-888888888888';
$tn = time() - 7200;
$e1 = kst($tn) . " [198.51.100.23][-][fakesess0123456789abcdefghij][error][app\\controllers\\PlayTimeApiController] [\n    'message' => 'Play time API action failed',\n    'route' => 'play-time-api/balance',\n    'exception' => 'yii\\base\\ErrorException',\n    'request_id' => '$RID1',\n    'client_fingerprint' => 'fp-FAKEidentityCOOKIE123456789',\n]\n"
    . kst($tn) . " [198.51.100.23][-][fakesess0123456789abcdefghij][info][application] \$_SERVER = [\n    'HTTP_X_REQUEST_ID' => '$RID1',\n    'REQUEST_METHOD' => 'POST',\n    'REQUEST_URI' => '/play-time-api/balance?token=FAKEtoken0123456789abcdefXYZ',\n    'HTTP_COOKIE' => '_csrf=csrfFAKEvalue9Q8W7E6R5T4Y3U2I1O0P; PHPSESSID=fakesess0123456789abcdefghij',\n    'REMOTE_ADDR' => '203.0.113.77',\n]\n";
file_put_contents("$tf/service1/app.log", entry(kst($tn - 86400 * 3), 'error', 'app', "old 'request_id' => '$RID1'") . $e1);
$e2 = kst($tn + 60) . " [-][-][-][warning][app\\components\\ExpectedHttpErrorHandler] [\n    'message' => 'Expected HTTP error',\n    'http_status' => 404,\n    'classification' => 'not_found',\n    'route' => 'play-time-api/unknown',\n    'suppressed_repeats' => 3,\n    'request_id' => '$RID2',\n]\n";
file_put_contents("$TR/tmp.log", $e2);
Fls\Proc::run(['/bin/sh', '-c', 'gzip -c tmp.log | cat > fx/10010/db/app.log.1.gz'], '', 10, $TR);
file_put_contents("$tf/db/app.log", entry(kst($tn + 100), 'warning', 'app', 'unrelated'));
file_put_contents("$tf/admin/app.log", spread($tn, $tn + 3000, 25, fn($ts) => entry($ts, 'warning', 'app', "repeat hit 'request_id' => '$RID4'")));
$cfgT = writeConfig("$TR/config.php", []);
$from = Tz::manila($tn - 3600, 'Y-m-d H:i');
$to = Tz::manila($tn + 3600 * 2, 'Y-m-d H:i');
[$rc, $out1, $err] = cli(['--request-id', $RID1, '--site', '10010', '--fixtures', "$TR/fx", '--config', $cfgT, '--from', $from, '--to', $to], ['TZ' => 'Asia/Dubai'], $TRAP);
T::contains($out1, $from . ' to ' . $to . ' Asia/Manila', '--from/--to pair is interpreted as Manila');
$utcShift = (new DateTimeImmutable($from . ':00', new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Asia/Manila'))->format('Y-m-d H:i');
T::notContains($out1, $utcShift . ' to ', '--from is not a UTC instant labeled Asia/Manila');
T::contains($out1, 'Failed: 500 (action threw yii\base\ErrorException) route play-time-api/balance', 'PlayTime failure worded as Failed: 500');
T::contains($out1, 'Request context dump (POST /play-time-api/balance); no status logged', '$_SERVER hit: method + query-stripped path only');
T::notContains($out1, 'old ', 'entry outside --from/--to excluded');
T::contains($out1, 'service1 earliest readable entry', 'earliest available time per role shown');
[$rc, $out2, $err] = cli(['--request-id', $RID2, '--site', '10010', '--fixtures', "$TR/fx", '--config', $cfgT, '--from', $from, '--to', $to], [], $TRAP);
T::contains($out2, 'Logged HTTP 404 (not_found) route play-time-api/unknown (3 repeats suppressed by dedup)', 'expected-HTTP hit in .gz: status + classification + suppressed repeats');
[$rc, $out3, $err] = cli(['--request-id', $RID3, '--site', '10010', '--fixtures', "$TR/fx", '--config', $cfgT], [], $TRAP);
T::contains($out3, 'Not found in readable logs. This codebase does not log a response status for successful requests.', 'no hit: exact not-found wording');
T::contains($out3, 'suppressed by the 5-minute dedup', 'no hit: dedup-suppressed case explained');
[$rc, $out4, $err] = cli(['--request-id', $RID4, '--site', '10010', '--fixtures', "$TR/fx", '--config', $cfgT], [], $TRAP);
T::eq(substr_count($out4, "\n  admin 2"), 20, 'trace capped at 20 entries');
T::contains($out4, 'more entr(ies) not shown', 'cap noted');
[$rc, $o, $e] = cli(['--request-id', $RID1, '--fixtures', "$TR/fx", '--config', $cfgT], [], $TRAP);
T::ok($rc === 2 && str_contains($e, '--site <id> is required'), 'trace without --site refused');
[$rc, $o, $e] = cli(['--request-id', 'not-a-uuid', '--site', '10010', '--fixtures', "$TR/fx", '--config', $cfgT], [], $TRAP);
T::eq($rc, 2, 'bad request id refused');
$cfgTL = writeConfig("$TR/config-live.php", ['live' => ['enabled' => true]]);
[$rc, $o, $e] = cli(['--request-id', $RID1, '--site', '10010', '--config', $cfgTL], [], $TRAP);
T::ok($rc === 7 && str_contains($e, 'per-run OK'), 'live trace refused without --per-run-ok');
$lr = (string)file_get_contents("$TR/data/state/last-run.json");
T::ok(str_contains($lr, '"hits"') && !str_contains($lr, 'Play time'), 'trace stores only hit counts');
assertNoLeaks($out1 . $out2 . $out3 . $out4 . allOutput("$TR/data"), 'trace outputs');

// ---------------------------------------------------------------- 10. safety switches
T::section('safety: live off, DISABLED, run.lock, permissions, scratch cleanup, plist');
$SF = tmpdir($WORK, 'safety');
$cfgD = writeConfig("$SF/config.php", []);
[$rc, $o, $e] = cli(['--site', '10010', '--config', $cfgD], [], $TRAP);
T::ok($rc === 7 && str_contains($e, 'live SSH runs are disabled'), 'default config: live SSH refused (exit 7)');
touch("$SF/data/state/DISABLED");
chmod("$SF/data/state/DISABLED", 0600);
[$rc, $o, $e] = cli(['--daily', '--config', $cfgD], [], $TRAP);
T::ok($rc === 3 && str_contains($o, 'state/DISABLED'), 'state/DISABLED stops --daily (exit 3)');
$lockFh = fopen("$SF/data/state/run.lock", 'c');
chmod("$SF/data/state/run.lock", 0600);
flock($lockFh, LOCK_EX);
[$rc, $o, $e] = cli(['--site', '10010', '--fixtures', $FX, '--config', $cfgD], [], $TRAP);
T::ok($rc === 4 && str_contains($e, 'run.lock'), 'run.lock held -> second run refused (exit 4)');
flock($lockFh, LOCK_UN);
fclose($lockFh);
file_put_contents("$SF/data/state/loose.json", '{}');
chmod("$SF/data/state/loose.json", 0644);
[$rc, $o, $e] = cli(['--site', '10010', '--fixtures', $FX, '--config', $cfgD], [], $TRAP);
T::ok($rc === 6 && str_contains($e, 'refusing to run'), 'group/world-readable state -> refuse (exit 6)');
unlink("$SF/data/state/loose.json");
// scratch removed on failure and on SIGTERM
$writeMap(array_map(fn($m) => ['dir' => $m['dir'], 'mode' => 'slow:6'], $map));
$cfgSig = writeConfig("$SF/config-sig.php", $liveCfg + ['data_dir' => "$SF/data-sig"]);
$e2env = getenv() + $env;
$e2env['PATH'] = $TRAP . ':' . getenv('PATH');
$p = proc_open([PHP_BIN, TOOL . '/fleet-log-scan.php', '--site', '10010', '--config', $cfgSig], [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pp, TOOL, $e2env);
$seen = false;
for ($i = 0; $i < 40 && !$seen; $i++) {
    usleep(100000);
    $seen = (bool)glob("$SF/data-sig/scratch/*");
}
T::ok($seen, 'scratch dir exists during a run');
proc_terminate($p, 15);
for ($i = 0; $i < 50 && proc_get_status($p)['running']; $i++) {
    usleep(100000);
}
proc_close($p);
T::eq(glob("$SF/data-sig/scratch/*") ?: [], [], 'scratch removed after SIGTERM');
$tamper = writeConfig("$SF/config-t.php", ['data_dir' => "$SF/data-t"]);
$realPin = (string)file_get_contents(TOOL . '/payload/payload.sha256');
$hashCopy = copyTool($WORK, 'hash-tamper');
file_put_contents($hashCopy . '/payload/payload.sha256', str_repeat('0', 64) . "  scan-v1.sh\n");
$hr = Fls\Proc::run([PHP_BIN, $hashCopy . '/fleet-log-scan.php', '--site', '10010', '--fixtures', $FX, '--config', $tamper], '', 60, $hashCopy, getenv() + ['PATH' => $TRAP . ':' . getenv('PATH')]);
T::eq(file_get_contents(TOOL . '/payload/payload.sha256'), $realPin, 'real payload.sha256 is not rewritten by the hash test');
T::ok($hr['exit'] === 2 && str_contains($hr['stderr'], 'hash mismatch'), 'payload hash mismatch refuses the run');
T::eq(glob("$SF/data-t/scratch/*") ?: [], [], 'scratch removed after a failed run');
$pl = (string)file_get_contents(TOOL . '/com.rti.fleet-log-scan.plist');
T::ok((bool)preg_match('#<key>Hour</key>\s*<integer>7</integer>\s*<key>Minute</key>\s*<integer>0</integer>#', $pl), 'plist template: Hour=7 Minute=0 (Dubai clock)');
T::ok(!file_exists(getenv('HOME') . '/Library/LaunchAgents/com.rti.fleet-log-scan.plist'), 'plist not installed in ~/Library/LaunchAgents');
T::ok(is_file(TOOL . '/state/DISABLED'), 'tool state/DISABLED present');
clearstatcache(true, TOOL . '/webhook.env');
T::ok(!file_exists(TOOL . '/webhook.env') || (fileperms(TOOL . '/webhook.env') & 0777) === 0600, 'no real webhook.env in the tool dir');
T::eq(file_exists("$TRAP/TRIPPED") ? file("$TRAP/TRIPPED", FILE_IGNORE_NEW_LINES) : [], [], 'trap: no real ssh/global/cursor-agent/openclaw/launchctl/curl was invoked');

// ---------------------------------------------------------------- 11. GNU/Linux payload parity (local Docker, mawk + GNU coreutils)
T::section('payload parity in local Linux Docker (no network)');
if (isset($opts['skip-docker'])) {
    echo "  skip docker (--skip-docker)\n";
} else {
    $img = 'mcr.microsoft.com/playwright:v1.61.0-noble';
    $dock = Fls\Proc::run(['/usr/local/bin/docker', 'image', 'inspect', $img], '', 30);
    if ($dock['exit'] !== 0) {
        T::ok(false, 'docker image available locally (not pulled by the tests)');
    } else {
        $since = (string)(time() - 2 * 86400);
        foreach (['30030/service1' => 'service', '11130/db' => 'db', '10010/db' => 'db'] as $rel => $role) {
            $mac = Fls\Proc::run(['/bin/bash', '-s', '--', "role=$role", "since=$since", 'max=52428800', "root=$FX/$rel"], (string)file_get_contents(TOOL . '/payload/scan-v1.sh'), 60, null, ['TZ' => 'Asia/Seoul', 'PATH' => '/usr/bin:/bin', 'LC_ALL' => 'C']);
            $lin = Fls\Proc::run(['/usr/local/bin/docker', 'run', '--rm', '-i', '--network', 'none', '-e', 'TZ=Asia/Seoul', '-e', 'LC_ALL=C', '-v', "$FX/$rel:/logs:ro", $img, 'bash', '-s', '--', "role=$role", "since=$since", 'max=52428800', 'root=/logs'], (string)file_get_contents(TOOL . '/payload/scan-v1.sh'), 120);
            $norm = function (string $o) {
                $l = array_values(array_filter(explode("\n", $o), fn($x) => str_starts_with($x, 'G') || str_starts_with($x, 'E')));
                sort($l);
                return $l;
            };
            $fl = fn(string $o) => preg_replace('/^F\t([^\t]*)\t(\w)\t\d+\t(\d+)\t(\d+)\t\d+\t/m', "F\t$1\t$2\tI\t$3\t$4\tM\t", implode("\n", array_filter(explode("\n", $o), fn($x) => str_starts_with($x, 'F'))));
            T::ok($lin['exit'] === 0 && $norm($mac['stdout']) === $norm($lin['stdout']) && count($norm($lin['stdout'])) > 1, "G/E records identical macOS vs Linux mawk for $rel");
            T::eq($fl($lin['stdout']), $fl($mac['stdout']), "F records identical (minus inode/mtime) for $rel");
            $awk = Fls\Proc::run(['/usr/local/bin/docker', 'run', '--rm', '--network', 'none', $img, 'sh', '-c', 'readlink -f "$(command -v awk)"; sed --version | head -1'], '', 60);
            if ($rel === '30030/service1') {
                echo '  linux tools: ' . str_replace("\n", ' | ', trim($awk['stdout'])) . "\n";
            }
        }
    }
}

// ---------------------------------------------------------------- summary
printf("\nRESULT: %d passed, %d failed (%.1fs)\n", T::$pass, T::$fail, microtime(true) - $t0);
foreach (T::$failures as $f) {
    echo "  FAILED: $f\n";
}
exit(T::$fail ? 1 : 0);
