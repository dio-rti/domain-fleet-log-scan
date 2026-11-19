#!/opt/homebrew/bin/php
<?php
// TEST STUB standing in for /usr/bin/ssh. It never opens a network connection and never calls ssh.
// It records argv, then runs the payload locally on a fixture dir mapped from the fake address.
// Map (JSON, env FLS_FAKE_SSH_MAP): {"<fake addr>": {"dir": "...", "mode": "ok|reset|hang|leak|slow:N|hostkey"}}
$log = getenv('FLS_FAKE_SSH_LOG');
$map = json_decode((string)@file_get_contents((string)getenv('FLS_FAKE_SSH_MAP')), true) ?: [];
$argv0 = $argv;
array_shift($argv0);
if ($log) {
    file_put_contents($log, json_encode($argv0) . "\n", FILE_APPEND);
}
$inner = end($argv0);
if (!preg_match('/wwkker@(\S+) "bash -s -- ([^"]*)"$/', (string)$inner, $m)) {
    fwrite(STDERR, "fake-ssh: unexpected command shape\n");
    exit(254);
}
$addr = $m[1];
$args = $m[2] === '' ? [] : explode(' ', $m[2]);
$cfg = $map[$addr] ?? null;
if ($cfg === null) {
    fwrite(STDERR, "ssh: connect to host port 22: Connection refused\n");
    exit(255);
}
$mode = $cfg['mode'] ?? 'ok';
$stdin = stream_get_contents(STDIN);
if ($mode === 'reset') {
    fwrite(STDERR, "kex_exchange_identification: read: Connection reset by peer\n");
    exit(255);
}
if ($mode === 'hostkey') {
    fwrite(STDERR, "Host key verification failed.\n");
    exit(255);
}
if ($mode === 'hang') {
    sleep(300);
    exit(0);
}
if (str_starts_with($mode, 'slow:')) {
    usleep((int)(1e6 * (float)substr($mode, 5)));
}
if ($mode === 'leak') {
    echo "H\tscan-v1\t" . time() . "\t+0900\tservice\n";
    echo "G\t-\terror\tapp\tleaked raw 203.0.113.77 _csrf mismatch PHPSESSID\t3\t2026-11-13 10:00:00\t2026-11-13 10:00:00\tapp.log\n";
    echo "G\t-\twarning\tapp\tclean template {n}\t2\t2026-11-13 10:00:00\t2026-11-13 10:00:00\tapp.log\n";
    echo "F\tapp.log\ty\t1\t10\t10\t" . time() . "\t2026-11-13 10:00:00\t-\t10\t5\n";
    echo "E\tscan-v1\tok\n";
    exit(0);
}
$p = proc_open(['/bin/bash', '-s', '--', ...$args, 'root=' . $cfg['dir']], [0 => ['pipe', 'r'], 1 => STDOUT, 2 => ['file', '/dev/null', 'w']], $pipes, null, ['TZ' => 'Asia/Seoul', 'PATH' => '/usr/bin:/bin', 'LC_ALL' => 'C']);
fwrite($pipes[0], $stdin);
fclose($pipes[0]);
exit(proc_close($p));
