#!/opt/homebrew/bin/php
<?php
// TEST STUB standing in for Dio's `global` CLI. No network. Serves synthetic JSON from env FLS_FAKE_GLOBAL (file).
// Shape: {"sites": {"jp": <json for site list>, ...}, "servers": {"10010": <json for server list>}, "fail": ["sg"]}
$data = json_decode((string)@file_get_contents((string)getenv('FLS_FAKE_GLOBAL')), true) ?: [];
if ($log = getenv('FLS_FAKE_GLOBAL_LOG')) {
    file_put_contents($log, json_encode(array_slice($argv, 1)) . "\n", FILE_APPEND);
}
$a = array_slice($argv, 1);
$profile = null;
$rest = [];
for ($i = 0; $i < count($a); $i++) {
    if ($a[$i] === '--profile') {
        $profile = $a[++$i];
        continue;
    }
    if (in_array($a[$i], ['--json', '--quiet', '--no-color', '--all'], true)) {
        continue;
    }
    if ($a[$i] === '--status') {
        $i++;
        continue;
    }
    $rest[] = $a[$i];
}
if (in_array($profile, $data['fail'] ?? [], true)) {
    fwrite(STDERR, "network error contacting https://ga.example.invalid\n");
    exit(10);
}
if ($rest[0] === 'site' && $rest[1] === 'list') {
    echo json_encode($data['sites'][$profile] ?? []);
    exit(0);
}
if ($rest[0] === 'server' && $rest[1] === 'list') {
    $s = $rest[2] ?? '';
    if (!isset($data['servers'][$s])) {
        fwrite(STDERR, "HTTP 404\n");
        exit(6);
    }
    echo json_encode($data['servers'][$s]);
    exit(0);
}
fwrite(STDERR, "unsupported in stub\n");
exit(2);
