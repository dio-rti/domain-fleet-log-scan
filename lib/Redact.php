<?php
declare(strict_types=1);

namespace Fls;

/**
 * Second redaction pass (PHP preg_replace with /i; never macOS sed) and the tripwire.
 * Placeholders use {braces} so they never re-match a class.
 */
final class Redact
{
    public const TLDS = 'com|net|org|io|kr|jp|sg|co|info|xyz|me|biz|cc|tv|asia|top|vip|club|site|online|app|dev|local|internal|lan|cloud|shop|live|bet|game|games|ph|vn|th|uk|edu|gov|de|fr|au|ca|us|eu|nl|se|no|fi|dk|ch|at|be|it|es|br|in|id|my|tw|hk';
    public const EXTS = 'php|phtml|log|js|json|css|html|htm|txt|gz|sh|xml|yml|yaml|ini|conf|png|jpg|jpeg|gif|svg|sql|csv|md|lock|tmp|bak|zip|tar|twig|tpl|env|pem|crt|key|map|vue|ts';

    public static function pass(string $s): string
    {
        $s = str_replace(["\t", "\r", "\n"], ' ', $s);
        $rules = [
            '/(?:set-)?cookie["\' ]*(?:=>|=|:).*/i' => 'cookie={secret}',
            // The whole authorization value, including a Bearer token that contains spaces.
            '/(?:proxy-)?authorization["\' ]*(?:=>|=|:).*/i' => 'authorization={secret}',
            // Before the generic secret cut, which used to stop at the first space and
            // leave the token after it had consumed the word Bearer.
            '/\bbearer\s+(?!\{)(?:"[^"]*"|\'[^\']*\'|[^,;&"\'()\]]+)/i' => 'bearer {token}',
            '/(?:password|passwd|pwd|secret|token|api_?key|access_?key|_csrf|csrf[a-z_]*|phpsessid|sessid|session_?id|auth|key)["\' ]*(?:=>|=|:)[ "\']*(?!\{)(?:"[^"]*"|\'[^\']*\'|[^,;&"\')\]]+)/i' => '{secret}',
            '/ey[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]*/i' => '{jwt}',
            '/[a-z][a-z0-9+.-]*:\/\/[^\] "\'<>]+/i' => '{url}',
            '/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i' => '{email}',
            '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i' => '{uuid}',
        ];
        foreach ($rules as $re => $ph) {
            $s = (string)preg_replace($re, $ph, $s);
        }
        $s = self::ipv6($s);
        $s = (string)preg_replace('/\d+\.\d+\.\d+\.\d+/', '{ip}', $s);
        $s = self::hosts($s);
        $s = (string)preg_replace_callback('/(?:\/[A-Za-z0-9_.@-]+)+\.php/', static fn($m) => basename($m[0]), $s);
        $s = (string)preg_replace('/[0-9a-f]{16,}/i', '{hex}', $s);
        $s = (string)preg_replace_callback('/[a-z0-9+\/=_-]{32,}/i', static fn($m) => preg_match('/[0-9+=]/', $m[0]) ? '{b64}' : $m[0], $s);
        $s = self::nums($s);
        $s = trim((string)preg_replace('/ {2,}/', ' ', $s));
        if (strlen($s) > 203) {
            $s = substr($s, 0, 200) . '...';
        }
        return $s;
    }

    /** Leading-compressed forms (::1) are short and start with ':'; still an address. */
    public static function isIpv6Token(string $t): bool
    {
        if (preg_match('/^::[0-9a-f]{1,4}(?::[0-9a-f]{0,4})*$/i', $t)) {
            return true;
        }
        $n = substr_count($t, ':');
        if (preg_match('/^\d{1,2}:\d{2}:\d{2}$/', $t)) {
            return false;
        }
        if (strlen($t) < 6 || !preg_match('/^[0-9a-f:]+$/i', $t)) {
            return false;
        }
        if ($n >= 3) {
            return true;
        }
        return $n >= 2 && str_contains($t, '::') && preg_match('/[a-f]/i', $t);
    }

    private static function ipv6(string $s): string
    {
        return (string)preg_replace_callback('/[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*(?![A-Za-z0-9])/i', static function ($m) {
            return self::isIpv6Token($m[0]) ? '{ip}' : $m[0];
        }, $s);
    }

    private static function hosts(string $s): string
    {
        return (string)preg_replace_callback(
            '/(?:[a-z0-9-]+\.)+([a-z]{2,24})(?![a-z0-9])/i',
            static function ($m) {
                $tld = strtolower($m[1]);
                if (preg_match('/^(?:' . self::EXTS . ')$/', $tld)) {
                    return $m[0];
                }
                if (preg_match('/^(?:' . self::TLDS . ')$/', $tld) || strlen($tld) <= 3) {
                    return '{host}';
                }
                return $m[0];
            },
            $s
        );
    }

    private static function nums(string $s): string
    {
        $out = '';
        $off = 0;
        while (preg_match('/\d+/', $s, $m, PREG_OFFSET_CAPTURE, $off)) {
            [$d, $pos] = $m[0];
            $pre = substr($s, 0, $pos);
            $prev = $pos > 0 ? $s[$pos - 1] : '';
            $next = substr($s, $pos + strlen($d), 1);
            $keep = (preg_match('/[A-Za-z_]/', $prev) && strlen($d) <= 2)
                || str_ends_with($pre, '.php:')
                || (strlen($d) === 3 && ($d[0] === '4' || $d[0] === '5') && !preg_match('/[0-9.]/', $next)
                    && preg_match('/(?:http|status|code|exception)[^a-z0-9]*$/i', substr($pre, -14)));
            $out .= substr($s, $off, $pos - $off) . ($keep ? $d : '{n}');
            $off = $pos + strlen($d);
        }
        return $out . substr($s, $off);
    }

    /**
     * Returns the leaked class name, or null when clean. $allow lists literal strings that may appear
     * (e.g. the request id the operator asked to trace).
     */
    public static function tripwire(string $s, array $allow = []): ?string
    {
        foreach ($allow as $a) {
            if ($a !== '') {
                $s = str_ireplace($a, '{allowed}', $s);
            }
        }
        if (preg_match_all('/[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*(?![A-Za-z0-9])/i', $s, $mm)) {
            foreach ($mm[0] as $t) {
                if (self::isIpv6Token($t)) {
                    return 'ipv6';
                }
            }
        }
        $classes = [
            'ipv4' => '/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/',
            'csrf' => '/_csrf/i',
            'session-id' => '/phpsessid/i',
            'cookie' => '/(?:set-)?cookie["\' ]*(?:=>|=|:)\s*(?!\{secret\})\S/i',
            'bearer' => '/\bbearer\s+(?!\{)(?:"[^"]+"|\'[^\']+\'|\S+)/i',
            'secret-kv' => '/(?:password|passwd|secret|token|api_?key)["\' ]*(?:=>|=|:)\s*(?!\{)[^\s,;]+/i',
            'jwt' => '/eyJ[\w-]{8,}\.[\w-]{8,}\./',
            'email' => '/[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}/i',
            'uuid' => '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i',
            'hostname' => '/(?<![A-Za-z0-9@_-])(?:[a-z0-9-]+\.)+(?!(?:' . self::EXTS . ')\b)(?:' . self::TLDS . '|[a-z]{2,3})(?![a-z0-9])/i',
            'long-digits' => '/\d{7,}/',
        ];
        foreach ($classes as $name => $re) {
            if (preg_match($re, $s)) {
                return $name;
            }
        }
        if (preg_match_all('/[A-Za-z0-9+\/=_-]{32,}/', $s, $mm)) {
            foreach ($mm[0] as $t) {
                if (preg_match('/[0-9+=]/', $t)) {
                    return 'base64';
                }
            }
        }
        return null;
    }
}