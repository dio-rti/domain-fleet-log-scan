<?php
declare(strict_types=1);

namespace Fls;

/**
 * Template family key (version 1). Collapses ids, quoted values, file:line and request paths so one
 * problem is one group. Idempotent: normalize(normalize($x)) === normalize($x).
 * Bump VERSION when the algorithm changes; history then re-baselines per role.
 */
final class Family
{
    public const VERSION = 1;

    private const FILE_LINE = '[A-Za-z_][A-Za-z0-9_]*\.php:\d++(?!\d|\xE2\x80\xA6|\.\.\.)';

    public static function normalize(string $tpl): string
    {
        // First physical line only: a stack frame must not change the key.
        $s = preg_split('/\r\n|\n|\r/', $tpl, 2)[0];

        // Unresolved request: the path is noise, the complete route File.php:line is kept as the suffix.
        $route = null;
        $at = strpos($s, 'Unable to resolve the request');
        if ($at !== false) {
            // Only a complete File.php:NNN that is the final token (optionally right before the ellipsis) counts.
            if (preg_match('/(?<![A-Za-z0-9_])(' . self::FILE_LINE . ')(?:\s+(?:\xE2\x80\xA6|\.\.\.))?\s*$/', $s, $m) === 1) {
                $route = $m[1];
            }
            $s = substr($s, 0, $at) . 'Unable to resolve the request {path}';
        }

        // command_id token: digits, hex, {n}, braces, underscores, hyphens stay one {id}.
        $s = (string)preg_replace('/command_id=(?:\{[a-z]+\}|[0-9A-Fa-f_-])+/', 'command_id={id}', $s);

        // Hex split by {n} (3+ pieces, mixed with hex digits), then a standalone hex run of 6+.
        $s = (string)preg_replace_callback(
            '/(?<![A-Za-z0-9_{}])(?:\{n\}|[0-9A-Fa-f]++){3,}(?![A-Za-z0-9_{}])/',
            static function (array $m): string {
                $rest = str_replace('{n}', '', $m[0]);
                return ($rest !== '' && str_contains($m[0], '{n}')) ? '{id}' : $m[0];
            },
            $s
        );
        // A standalone run must contain a digit or {n} piece (already handled above) so words like "decade" survive.
        $s = (string)preg_replace('/\b(?=[0-9A-Fa-f]*[0-9])[0-9A-Fa-f]{6,}\b/', '{id}', $s);

        // Undefined index/key/offset <name>.
        $s = (string)preg_replace('/Undefined (?:array )?(?:index|key|offset)\b:?\s*(?:"[^"]*"|\'[^\']*\'|\S+)/', 'Undefined array key {key}', $s);

        // Quoted strings.
        $s = (string)preg_replace('/"[^"]*"/', '{q}', $s);
        // Single quotes only as real quoting: the opening quote follows start, whitespace, = : ( [ and the closing
        // quote precedes end, whitespace or ) ] , . ; : so apostrophes in prose (user's ... isn't) are not paired.
        $s = (string)preg_replace("/(?<=^|[\s=:(\[])'[^']*'(?=$|[\s)\],.;:])/", '{q}', $s);

        // "in File.php:line" on what is left.
        $s = (string)preg_replace('/\bin (?:[\w.\\\\\/-]*[\\\\\/])?[A-Za-z_][A-Za-z0-9_]*\.php:\d+/', 'in {file}', $s);

        $s = str_replace(["\xE2\x80\xA6", '...'], '', $s);
        $s = trim((string)preg_replace('/\s+/', ' ', $s));

        return $route !== null ? $s . ' in ' . $route : $s;
    }
}
