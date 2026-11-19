#!/opt/homebrew/bin/php
<?php
// TEST STUB standing in for cursor-agent. No network. Records argv/cwd/stdin; FLS_STUB_MODE=fail exits 1.
$cap = getenv('FLS_STUB_CAPTURE');
if ($cap) {
    $cwd = getcwd() ?: '';
    $n = 0;
    if ($cwd !== '' && is_dir($cwd)) {
        $n = count(array_diff(scandir($cwd) ?: [], ['.', '..']));
    }
    file_put_contents($cap, json_encode(['argv' => array_slice($argv, 1), 'cwd' => $cwd, 'cwd_entries' => $n, 'stdin' => stream_get_contents(STDIN)]) . "\n", FILE_APPEND);
}
if (getenv('FLS_STUB_MODE') === 'fail') {
    fwrite(STDERR, "model unavailable\n");
    exit(1);
}
echo "One new fatal group on a db server.\nOne admin warning is running at about 3x its usual rate.\nNo scan failures.\n";
