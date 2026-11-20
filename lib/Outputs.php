<?php
declare(strict_types=1);

namespace Fls;

/**
 * Optional webhook: one redacted summary JSON per run. Config from a 0600 env file
 * (WEBHOOK_URL, WEBHOOK_AUTH_HEADER, optional WEBHOOK_TIMEOUT<=10). Zero retries.
 * The URL and auth value are never printed, logged or stored.
 */
final class Webhook
{
    public ?string $url = null;
    private ?string $auth = null;
    public float $timeout = 10.0;
    public ?string $disabledReason = null;

    public static function fromEnvFile(string $path): self
    {
        $w = new self();
        if (!is_file($path)) {
            $w->disabledReason = 'webhook.env missing';
            return $w;
        }
        if ((fileperms($path) & 0077) !== 0) {
            $w->disabledReason = 'webhook.env permissions too open (need 0600)';
            return $w;
        }
        foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || !str_contains($line, '=')) {
                continue;
            }
            [$k, $v] = array_map('trim', explode('=', $line, 2));
            $v = trim($v, "\"'");
            match ($k) {
                'WEBHOOK_URL' => $w->url = $v,
                'WEBHOOK_AUTH_HEADER' => $w->auth = $v,
                'WEBHOOK_TIMEOUT' => $w->timeout = max(1.0, min(10.0, (float)$v)),
                default => null,
            };
        }
        if ($w->url === null || $w->url === '') {
            $w->url = null;
            $w->disabledReason = 'webhook.env has no WEBHOOK_URL';
        } elseif (!preg_match('~^https?://[^\s/]+~i', $w->url)) {
            $w->url = null;
            $w->disabledReason = 'WEBHOOK_URL must be http(s)';
        }
        if ($w->auth !== null && preg_match('/[\r\n]/', $w->auth)) {
            $w->auth = null;
        }
        return $w;
    }

    public function enabled(): bool
    {
        return $this->url !== null;
    }

    public function isLoopback(): bool
    {
        $h = strtolower((string)parse_url((string)$this->url, PHP_URL_HOST));
        return in_array($h, ['127.0.0.1', 'localhost', '[::1]', '::1'], true);
    }

    /** Remove URL, host and auth value from any text before it is shown. */
    public function mask(string $s): string
    {
        foreach ([$this->url, $this->auth, (string)parse_url((string)$this->url, PHP_URL_HOST)] as $secret) {
            if ($secret) {
                $s = str_replace($secret, '<webhook-redacted>', $s);
            }
        }
        if ($this->auth && preg_match('/\S+$/', $this->auth, $m)) {
            $s = str_replace($m[0], '<webhook-redacted>', $s);
        }
        return (string)preg_replace('/(authorization|bearer)\s*[:=]?\s*\S+/i', '$1 <webhook-redacted>', $s);
    }

    /** Build the redacted payload. Rows that trip the tripwire are dropped and counted. */
    public static function payload(array $run): array
    {
        $items = [];
        $dropped = 0;
        foreach ($run['flags'] as $f) {
            $row = [
                'site' => $f['site'], 'role' => $f['role'], 'flag' => $f['flag'], 'level' => $f['level'],
                'category' => $f['category'], 'template' => $f['template'], 'count' => $f['count'],
                'rate_per_h' => round($f['rate'], 2), 'usual' => $f['usual'] === null ? null : (int)round($f['usual']),
                'factor' => $f['factor'] === null ? null : round($f['factor'], 1),
            ];
            if (Redact::tripwire(json_encode($row, JSON_UNESCAPED_SLASHES)) !== null) {
                $dropped++;
                continue;
            }
            $items[] = $row;
        }
        $failures = array_map(fn($f) => ['site' => $f['site'], 'role' => $f['role'], 'status' => $f['status']], $run['failures']);
        $sev = 'info';
        if ($items || $run['baseline_sites']) {
            $sev = 'warning';
        }
        if ($failures || array_filter($items, fn($i) => $i['flag'] === 'new-fatal')) {
            $sev = 'critical';
        }
        $notes = array_values(array_filter(array_merge($run['observations'], $run['notes']), fn($n) => Redact::tripwire($n) === null));
        $summary = $run['summary'] ?? null;
        if ($summary !== null && Redact::tripwire($summary) !== null) {
            $summary = null;
            $dropped++;
        }
        return [
            'schema' => 'fleet-log-scan.webhook.v1',
            'run_id' => $run['run_id'],
            'mode' => $run['mode'],
            'generated_at' => Tz::manila($run['started'], 'Y-m-d H:i') . ' Asia/Manila',
            'severity' => $sev,
            'changed' => (bool)($items || $run['baseline_sites']),
            'baseline_sites' => $run['baseline_sites'],
            'servers' => ['scanned' => $run['servers'], 'failed' => count($failures)],
            'items' => $items,
            'failures' => $failures,
            'notes' => $notes,
            'summary' => $summary,
            'summary_status' => $run['summary_status'] ?? 'disabled',
            'dropped_by_tripwire' => $dropped,
            'payload_versions' => $run['payload_versions'] ?? [],
        ];
    }

    /** POST once. Returns a masked status string; never throws. */
    public function post(array $payload): string
    {
        return $this->postResult($payload)['status'];
    }

    /** @return array{code:int, body:string, status:string} */
    public function postResult(array $payload): array
    {
        if (!$this->enabled()) {
            return ['code' => 0, 'body' => '', 'status' => 'webhook disabled: ' . $this->disabledReason];
        }
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $headers = "Content-Type: application/json\r\nUser-Agent: fleet-log-scan/1\r\n";
        if ($this->auth) {
            $headers .= 'Authorization: ' . $this->auth . "\r\n";
        }
        $ctx = stream_context_create(['http' => [
            'method' => 'POST', 'header' => $headers, 'content' => $body, 'timeout' => $this->timeout,
            'ignore_errors' => true, 'follow_location' => 0, 'max_redirects' => 0,
        ]]);
        $old = ini_set('default_socket_timeout', (string)(int)ceil($this->timeout));
        $err = null;
        set_error_handler(function ($no, $msg) use (&$err) {
            $err = $msg;
            return true;
        });
        try {
            $resp = @file_get_contents((string)$this->url, false, $ctx);
            $hdr = $http_response_header ?? [];
        } finally {
            restore_error_handler();
            ini_set('default_socket_timeout', (string)$old);
        }
        $code = 0;
        if (isset($hdr[0]) && preg_match('/\s(\d{3})\s?/', $hdr[0], $m)) {
            $code = (int)$m[1];
        }
        if ($resp === false && $code === 0) {
            $why = $err && stripos($err, 'timed out') !== false ? 'timeout' : 'connection failed';
            return ['code' => 0, 'body' => '', 'status' => 'webhook delivery error: ' . $why];
        }
        $status = $code >= 200 && $code < 300 ? 'webhook sent (HTTP ' . $code . ')' : 'webhook delivery error: HTTP ' . $code;
        return ['code' => $code, 'body' => $resp === false ? '' : (string)$resp, 'status' => $status];
    }
}

/**
 * Optional three-line summary via Cursor CLI with --model grok-4.7-xhigh-fast passed explicitly.
 * Input is the already redacted digest; it is re-redacted and tripwired here before any call.
 */
final class Summary
{
    public const SKIPPED = 'summary skipped: model unavailable';

    public static function argv(array $cfg, string $prompt): array
    {
        $name = Config::modelName($cfg);
        return [$cfg['model']['bin'], '-p', '--model', $name, '--mode', 'ask', '--output-format', 'text', $prompt];
    }

    /** @return array{0:?string,1:string} [summary, status] */
    public static function run(array $cfg, string $digest): array
    {
        if (empty($cfg['model']['enabled'])) {
            return [null, 'disabled'];
        }
        try {
            Config::modelName($cfg);
        } catch (FlsException) {
            return [null, self::SKIPPED];
        }
        $clean = implode("\n", array_map([Redact::class, 'pass'], explode("\n", $digest)));
        if (Redact::tripwire($clean) !== null) {
            return [null, 'summary skipped: redaction tripwire'];
        }
        $prompt = "Summarize this redacted fleet log-scan digest in at most three short lines for an on-call engineer. Do not invent facts. Digest:\n" . $clean;
        $bin = (string)$cfg['model']['bin'];
        if (!is_file($bin) || !is_executable($bin)) {
            return [null, self::SKIPPED];
        }
        // The digest is the only input. Do not start the model in the tool tree
        // or the OpenClaw workspace (those can hold webhook.env and server names).
        $iso = self::isolatedCwd($cfg);
        if ($iso === null) {
            return [null, self::SKIPPED];
        }
        try {
            $r = Proc::run(self::argv($cfg, $prompt), '', (int)$cfg['model']['timeout'], $iso);
        } finally {
            self::removeIso($iso);
        }
        if ($r['exit'] !== 0 || $r['timedOut'] || trim($r['stdout']) === '') {
            return [null, self::SKIPPED];
        }
        $lines = array_slice(array_values(array_filter(array_map('trim', explode("\n", $r['stdout'])), 'strlen')), 0, 3);
        $out = implode(' / ', array_map([Redact::class, 'pass'], $lines));
        if (Redact::tripwire($out) !== null) {
            return [null, 'summary skipped: redaction tripwire'];
        }
        return [$out, 'summary ok'];
    }

    /** Empty directory outside the tool tree and the OpenClaw workspace. */
    private static function isolatedCwd(array $cfg): ?string
    {
        $base = realpath(sys_get_temp_dir());
        if ($base === false) {
            return null;
        }
        $dir = $base . '/fls-sum-' . bin2hex(random_bytes(8));
        if (!@mkdir($dir, 0700)) {
            return null;
        }
        $real = realpath($dir);
        if ($real === false || !str_starts_with($real, $base . '/') || !str_starts_with(basename($real), 'fls-sum-')) {
            if (is_dir($dir)) {
                @rmdir($dir);
            }
            return null;
        }
        $roots = [];
        foreach (['tool_dir', 'data_dir'] as $k) {
            if (!empty($cfg[$k])) {
                $r = realpath((string)$cfg[$k]);
                if ($r !== false) {
                    $roots[] = $r;
                }
            }
        }
        foreach ([(string)($cfg['model']['cwd'] ?? ''), (string)getenv('HOME') . '/.openclaw/workspace-abella'] as $p) {
            if ($p !== '') {
                $r = realpath($p);
                if ($r !== false) {
                    $roots[] = $r;
                }
            }
        }
        foreach ($roots as $root) {
            if ($real === $root || str_starts_with($real, $root . '/')) {
                @rmdir($real);
                return null;
            }
        }
        $left = array_diff(scandir($real) ?: [], ['.', '..']);
        if ($left) {
            self::removeIso($real);
            return null;
        }
        return $real;
    }

    private static function removeIso(string $dir): void
    {
        $base = realpath(sys_get_temp_dir());
        $real = realpath($dir);
        if ($base === false || $real === false || $real === $base || !str_starts_with($real, $base . '/')) {
            return;
        }
        if (!str_starts_with(basename($real), 'fls-sum-')) {
            return;
        }
        Fs::rmTree($real);
    }
}

/**
 * Human channel: OpenClaw message to Dio. Not auto-fired: the digest is queued in outbox/ as
 * pending until a later standing OK enables delivery.openclaw and supplies argv.
 */
final class Delivery
{
    public static function queue(array $cfg, string $runId, string $digest, bool $allowFire): string
    {
        $file = $cfg['data_dir'] . '/outbox/' . $runId . '.json';
        $d = $cfg['delivery']['openclaw'];
        $status = 'pending-not-fired';
        if ($allowFire && !empty($d['enabled']) && !empty($d['argv'])) {
            $r = Proc::run(array_values($d['argv']), $digest, 30);
            $status = $r['exit'] === 0 ? 'delivered' : 'delivery error (exit ' . $r['exit'] . ')';
        }
        Fs::writeJson($file, ['run_id' => $runId, 'channel' => 'openclaw-message-to-dio', 'status' => $status, 'text' => $digest]);
        return $status;
    }
}
