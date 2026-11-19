<?php
declare(strict_types=1);

namespace Fls;

final class FlsException extends \RuntimeException {}

/** Time helpers. Everything is epoch internally; display is Asia/Manila. Never uses the host zone. */
final class Tz
{
    public const DISPLAY = 'Asia/Manila';

    public static function manila(int $epoch, string $fmt = 'Y-m-d H:i'): string
    {
        return (new \DateTimeImmutable('@' . $epoch))->setTimezone(new \DateTimeZone(self::DISPLAY))->format($fmt);
    }

    public static function manilaDate(int $epoch): string
    {
        return self::manila($epoch, 'Y-m-d');
    }

    /** Server log timestamp (local server time) + server UTC offset ("+0900") -> epoch. */
    public static function serverTsToEpoch(string $ts, string $offset): ?int
    {
        if (!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $ts) || !preg_match('/^[+-]\d{4}$/', $offset)) {
            return null;
        }
        $d = \DateTimeImmutable::createFromFormat('Y-m-d H:i:s O', $ts . ' ' . $offset);
        return $d === false ? null : $d->getTimestamp();
    }

    /**
     * Parse a Manila wall-clock time given on the CLI ("2026-11-13 08:00" or with seconds).
     * '!' zeroes omitted fields but also pins the zone to UTC, and the DateTimeZone
     * argument does not win on every PHP build. Take the clock numbers and apply
     * Asia/Manila explicitly so the process zone cannot shift the instant.
     */
    public static function parseManila(string $s): ?int
    {
        foreach (['Y-m-d H:i:s', 'Y-m-d H:i', 'Y-m-d'] as $f) {
            $parsed = \DateTimeImmutable::createFromFormat('!' . $f, $s, new \DateTimeZone('UTC'));
            if ($parsed === false || $parsed->format($f) !== $s) {
                continue;
            }
            $local = new \DateTimeImmutable($parsed->format('Y-m-d H:i:s'), new \DateTimeZone(self::DISPLAY));
            return $local->getTimestamp();
        }
        return null;
    }
}

/** Filesystem helpers: 0700 dirs, 0600 files, atomic writes. */
final class Fs
{
    public static function ensureDir(string $dir): void
    {
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new FlsException('cannot create directory ' . basename($dir));
        }
        chmod($dir, 0700);
    }

    public static function writeSecure(string $path, string $data): void
    {
        self::ensureDir(dirname($path));
        $tmp = $path . '.tmp' . getmypid();
        if (file_put_contents($tmp, $data) === false) {
            throw new FlsException('cannot write ' . basename($path));
        }
        chmod($tmp, 0600);
        rename($tmp, $path);
    }

    public static function readJson(string $path, array $default = []): array
    {
        if (!is_file($path)) {
            return $default;
        }
        $j = json_decode((string)file_get_contents($path), true);
        return is_array($j) ? $j : $default;
    }

    public static function writeJson(string $path, array $data): void
    {
        self::writeSecure($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    }

    public static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($dir);
    }

    /** Returns relative paths that are group/world accessible under the given roots. */
    public static function loosePerms(string $base, array $relRoots): array
    {
        $bad = [];
        foreach ($relRoots as $rel) {
            $p = $base . '/' . $rel;
            if (!file_exists($p)) {
                continue;
            }
            $items = [$p];
            if (is_dir($p)) {
                $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($p, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::SELF_FIRST);
                foreach ($it as $f) {
                    $items[] = $f->getPathname();
                }
            }
            foreach ($items as $i) {
                if (is_link($i)) {
                    continue;
                }
                if ((fileperms($i) & 0077) !== 0) {
                    $bad[] = substr($i, strlen($base) + 1);
                }
            }
        }
        return $bad;
    }
}

/** Exclusive run lock (flock: released automatically if the process dies, so no stale lock). */
final class Lock
{
    /** @var resource|null */
    private $fh = null;

    public function __construct(private string $path) {}

    public function acquire(): bool
    {
        Fs::ensureDir(dirname($this->path));
        $fh = fopen($this->path, 'c');
        if ($fh === false) {
            return false;
        }
        chmod($this->path, 0600);
        if (!flock($fh, LOCK_EX | LOCK_NB)) {
            fclose($fh);
            return false;
        }
        ftruncate($fh, 0);
        fwrite($fh, (string)getmypid());
        $this->fh = $fh;
        return true;
    }

    public function release(): void
    {
        if ($this->fh) {
            flock($this->fh, LOCK_UN);
            fclose($this->fh);
            $this->fh = null;
        }
    }
}

/** Run a command (argv array, no shell) with stdin, timeout and output cap. Stderr is captured but callers must not log it raw. */
final class Proc
{
    /** @return array{exit:int, stdout:string, stderr:string, timedOut:bool} */
    public static function run(array $argv, string $stdin = '', int $timeout = 30, ?string $cwd = null, ?array $env = null, int $cap = 4194304): array
    {
        $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $p = @proc_open($argv, $spec, $pipes, $cwd, $env);
        if (!is_resource($p)) {
            return ['exit' => 127, 'stdout' => '', 'stderr' => 'spawn failed', 'timedOut' => false];
        }
        if ($stdin !== '') {
            @fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = $err = '';
        $start = microtime(true);
        $timedOut = false;
        while (true) {
            $r = [$pipes[1], $pipes[2]];
            $w = $e = null;
            @stream_select($r, $w, $e, 0, 100000);
            $out .= (string)@fread($pipes[1], 65536);
            $err .= (string)@fread($pipes[2], 65536);
            $st = proc_get_status($p);
            if (!$st['running']) {
                $out .= (string)stream_get_contents($pipes[1]);
                $err .= (string)stream_get_contents($pipes[2]);
                $code = $st['exitcode'];
                break;
            }
            if (microtime(true) - $start > $timeout || strlen($out) > $cap) {
                $timedOut = true;
                proc_terminate($p, 15);
                usleep(300000);
                $st = proc_get_status($p);
                if ($st['running']) {
                    proc_terminate($p, 9);
                }
                $code = 124;
                break;
            }
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        $c = proc_close($p);
        if (!isset($code) || $code === -1) {
            $code = $c;
        }
        return ['exit' => (int)$code, 'stdout' => $out, 'stderr' => $err, 'timedOut' => $timedOut];
    }
}
