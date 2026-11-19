<?php
declare(strict_types=1);

namespace Fls;

/** Fixed, versioned, hashed and linted remote payloads. */
final class Payload
{
    public const ARG_KEYS = [
        'scan-v1.sh' => ['role', 'since', 'max', 'ck', 'root'],
        'trace-v1.sh' => ['id', 'from', 'to', 'root'],
    ];

    private const FORBIDDEN_WORDS = [
        'rm', 'mv', 'cp', 'tee', 'yii', 'mysql', 'mysqldump', 'curl', 'wget', 'kill', 'pkill', 'killall',
        'chmod', 'chown', 'chgrp', 'dd', 'truncate', 'shred', 'sudo', 'su', 'scp', 'sftp', 'ssh', 'nc', 'ncat',
        'socat', 'rsync', 'ln', 'mkdir', 'rmdir', 'touch', 'install', 'eval', 'exec', 'source', 'crontab',
        'systemctl', 'shutdown', 'reboot', 'system', 'getline', 'fflush', 'mktemp', 'xargs', 'nohup', 'unlink',
        'python', 'python3', 'perl', 'php', 'ruby', 'node', 'nodejs',
    ];

    /** @return string[] lint problems (empty = clean) */
    public static function lint(string $src): array
    {
        $bad = [];
        if (str_contains($src, '>')) {
            $bad[] = 'write redirection (>)';
        }
        foreach (self::FORBIDDEN_WORDS as $w) {
            if (preg_match('/(?<![A-Za-z0-9_-])' . preg_quote($w, '/') . '(?![A-Za-z0-9_-])/', $src)) {
                $bad[] = 'forbidden token: ' . $w;
            }
        }
        if (preg_match('/\bsed\b[^\n|;]*(?:\s-[a-zA-Z]*i|--in-place)/', $src)) {
            $bad[] = 'sed -i';
        }
        // w/e are sed write/execute. The flag is not always followed by whitespace
        // (sed 's/a/b/e'). The sed -e script option is not this flag: '-' is not in the class.
        if (preg_match('/\bsed\b[^\n|;]*[\'"\s;\/}](?:w|W|e)(?:\s|[\'"`;|&]|$)/', $src)) {
            $bad[] = 'sed write/exec command';
        }
        if (preg_match('/\b(?:bash|sh|zsh|dash)\s+-c\b/', $src) || preg_match('/\|\s*(?:bash|sh|zsh|dash)\b/', $src)) {
            $bad[] = 'nested shell';
        }
        if (preg_match('/\bawk\b[^\n]*\s-i\s/', $src)) {
            $bad[] = 'awk -i';
        }
        return $bad;
    }

    /** Load a payload; refuses on hash mismatch or lint failure. */
    public static function load(string $toolDir, string $name): string
    {
        if (!isset(self::ARG_KEYS[$name])) {
            throw new FlsException('unknown payload ' . $name);
        }
        $file = $toolDir . '/payload/' . $name;
        $src = (string)@file_get_contents($file);
        $want = self::expectedHash($toolDir, $name);
        if ($want === null || !hash_equals($want, hash('sha256', $src))) {
            throw new FlsException('payload hash mismatch for ' . $name . ' (refusing to send)');
        }
        $lint = self::lint($src);
        if ($lint) {
            throw new FlsException('payload lint failed for ' . $name . ': ' . implode(', ', $lint));
        }
        return $src;
    }

    public static function expectedHash(string $toolDir, string $name): ?string
    {
        $lines = @file($toolDir . '/payload/payload.sha256', FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $l) {
            if (preg_match('/^([0-9a-f]{64})\s+\*?(\S+)$/', trim($l), $m) && $m[2] === $name) {
                return $m[1];
            }
        }
        return null;
    }

    /**
     * Validate and render payload args. Values may only use [0-9A-Za-z._:/-].
     * `root` (log root override) is accepted only for local fixture runs.
     */
    public static function args(string $name, array $kv, bool $allowRoot): array
    {
        $out = [];
        foreach ($kv as [$k, $v]) {
            if (!in_array($k, self::ARG_KEYS[$name], true)) {
                throw new FlsException('payload arg not allowed: ' . $k);
            }
            if ($k === 'root' && !$allowRoot) {
                throw new FlsException('root= is only allowed in --fixtures mode');
            }
            $v = (string)$v;
            if ($v === '' || !preg_match('/^[0-9A-Za-z._:\/-]+$/', $v)) {
                throw new FlsException('payload arg value rejected for ' . $k);
            }
            $out[] = $k . '=' . $v;
        }
        return $out;
    }
}
