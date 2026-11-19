<?php
declare(strict_types=1);

namespace Fls;

/**
 * Parses payload TSV (H/F/G/E for scan, H/M/R/E for trace). Runs the PHP redaction pass on every
 * text field and the tripwire on the result; leaking rows are dropped and counted.
 */
final class Tsv
{
    public ?array $header = null;
    public array $files = [];
    public array $groups = [];
    public array $matches = [];
    public array $ranges = [];
    public bool $complete = false;
    public ?string $error = null;
    public int $tripwire = 0;
    public array $tripClasses = [];
    public int $malformed = 0;

    public static function parse(string $out, array $allow = []): self
    {
        $t = new self();
        foreach (preg_split('/\R/', $out) as $line) {
            if ($line === '') {
                continue;
            }
            $f = explode("\t", $line);
            switch ($f[0]) {
                case 'H':
                    if (($f[2] ?? '') === 'ERR') {
                        $t->error = 'payload-error:' . preg_replace('/[^a-z-]/', '', $f[3] ?? '');
                    } elseif (count($f) >= 4 && preg_match('/^\d+$/', $f[2]) && preg_match('/^[+-]\d{4}$/', $f[3])) {
                        $t->header = ['version' => $f[1], 'epoch' => (int)$f[2], 'offset' => $f[3], 'role' => $f[4] ?? ''];
                    } else {
                        $t->malformed++;
                    }
                    break;
                case 'F':
                    if (count($f) < 11) {
                        $t->malformed++;
                        break;
                    }
                    if (!preg_match('/^[A-Za-z0-9._\/-]+$/', $f[1])) {
                        $t->malformed++;
                        break;
                    }
                    $t->files[$f[1]] = [
                        'label' => $f[1], 'readable' => $f[2] === 'y', 'inode' => $f[3], 'size' => $f[4], 'offset' => $f[5],
                        'mtime' => $f[6], 'last_ts' => $f[7], 'flags' => $f[8] === '-' ? [] : explode(',', $f[8]),
                        'bytes' => (int)$f[9], 'entries' => (int)$f[10],
                        'prefix_len' => (isset($f[11]) && preg_match('/^\d+$/', $f[11])) ? (int)$f[11] : 0,
                        'prefix_sum' => (isset($f[12]) && preg_match('/^\d+$/', $f[12])) ? $f[12] : '-',
                    ];
                    break;
                case 'G':
                    if (count($f) < 9 || !preg_match('/^\d+$/', $f[5])) {
                        $t->malformed++;
                        break;
                    }
                    $level = strtolower($f[2]);
                    $cat = Redact::pass($f[3]);
                    $tpl = Redact::pass($f[4]);
                    $leak = Redact::tripwire($cat . ' ' . $tpl);
                    if ($leak !== null) {
                        $t->tripwire++;
                        $t->tripClasses[$leak] = true;
                        break;
                    }
                    $t->groups[] = [
                        'level' => in_array($level, ['error', 'warning'], true) ? $level : 'other',
                        'category' => $cat, 'template' => $tpl, 'count' => (int)$f[5],
                        'first' => $f[6], 'last' => $f[7], 'label' => $f[8],
                    ];
                    break;
                case 'M':
                    if (count($f) < 7) {
                        $t->malformed++;
                        break;
                    }
                    $row = ['label' => $f[1], 'ts' => $f[2], 'level' => strtolower($f[3]), 'category' => Redact::pass($f[4]), 'head' => Redact::pass($f[5]), 'kv' => []];
                    foreach (explode(';', $f[6]) as $pair) {
                        if (!str_contains($pair, '=')) {
                            continue;
                        }
                        [$k, $v] = explode('=', $pair, 2);
                        if (in_array($k, ['http_status', 'suppressed_repeats'], true)) {
                            if (preg_match('/^\d{1,6}$/', $v)) {
                                $row['kv'][$k] = $v;
                            }
                            continue;
                        }
                        $row['kv'][$k] = in_array($v, $allow, true) ? $v : Redact::pass($v);
                    }
                    $leak = Redact::tripwire(json_encode($row, JSON_UNESCAPED_SLASHES), $allow);
                    if ($leak !== null) {
                        $t->tripwire++;
                        $t->tripClasses[$leak] = true;
                        break;
                    }
                    $t->matches[] = $row;
                    break;
                case 'R':
                    if (count($f) >= 4) {
                        $t->ranges[$f[1]] = ['earliest' => $f[2], 'hits' => (int)$f[3]];
                    }
                    break;
                case 'E':
                    $t->complete = ($f[2] ?? '') === 'ok';
                    break;
                default:
                    $t->malformed++;
            }
        }
        if ($t->header === null && $t->error === null) {
            $t->error = 'no-header';
        }
        return $t;
    }
}
