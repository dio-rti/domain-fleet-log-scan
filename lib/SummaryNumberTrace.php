<?php

declare(strict_types=1);

namespace Fls;

use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/**
 * Number trace for ai_summary text (plan section 3). A token fails closed.
 * The first failing token is returned for logs; Iris responses never include it.
 */
final class SummaryNumberTrace
{
    public const FALLBACK_ZONE = 'Asia/Dubai';

    private const RFC3339 = '/^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/';

    public static function isRfc3339(string $s): bool
    {
        return preg_match(self::RFC3339, $s) === 1;
    }

    /** @param array<string,mixed>|object $doc */
    public static function displayZone(array|object $doc): DateTimeZone
    {
        $note = (string) (self::toArray($doc)['timing']['timezone_note'] ?? '');
        if (preg_match_all('/[A-Za-z][A-Za-z0-9_+-]*(?:\/[A-Za-z][A-Za-z0-9_+-]*)+/', $note, $m)) {
            foreach ($m[0] as $token) {
                try {
                    return new DateTimeZone($token);
                } catch (Throwable) {
                    continue;
                }
            }
        }
        foreach (preg_split('/\s+/', trim($note)) ?: [] as $word) {
            $word = trim($word, ".,;:");
            if ($word === '') {
                continue;
            }
            try {
                return new DateTimeZone($word);
            } catch (Throwable) {
                continue;
            }
        }
        return new DateTimeZone(self::FALLBACK_ZONE);
    }

    /**
     * @param array<string,mixed>|object $doc
     * @return array<string,mixed>
     */
    public static function toArray(array|object $doc): array
    {
        if (is_array($doc)) {
            return $doc;
        }
        $decoded = json_decode(json_encode($doc, JSON_THROW_ON_ERROR), true, 64, JSON_THROW_ON_ERROR);
        return is_array($decoded) ? $decoded : [];
    }

    /** @param array<string,mixed>|object $doc */
    public static function firstUntraced(string $text, array|object $doc): ?string
    {
        $source = self::toArray($doc);
        unset($source['ai_summary'], $source['payload_hash']);
        $zone = self::displayZone($source);
        $allowed = [];
        $strings = [];
        self::walk($source, $allowed, $strings);
        $sites = $source['scope']['sites'] ?? null;
        if (is_array($sites)) {
            self::addInt($allowed, count($sites));
        }
        foreach ($strings as $s) {
            if (self::isRfc3339($s)) {
                self::addClockParts($allowed, $s, $zone);
            }
        }

        $matches = [];
        self::collect($text, '/\d+\.\d+/', 'dec', $matches);
        self::collect($text, '/\d+%/', 'pct', $matches);
        self::collect($text, '/(?<![A-Za-z0-9_])(?<![.,])(\d{1,3}(?:,\d{3})+|\d+)(?![A-Za-z0-9_])(?![.,]\d)/', 'int', $matches);
        usort($matches, static function (array $a, array $b): int {
            return $a['start'] <=> $b['start'] ?: $b['len'] <=> $a['len'];
        });
        $consumed = 0;
        foreach ($matches as $m) {
            if ($m['start'] < $consumed) {
                continue;
            }
            $consumed = $m['start'] + $m['len'];
            if ($m['kind'] === 'int') {
                if (!isset($allowed[self::norm($m['text'])])) {
                    return $m['text'];
                }
                continue;
            }
            $found = false;
            foreach ($strings as $s) {
                if (str_contains($s, $m['text'])) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                return $m['text'];
            }
        }
        return null;
    }

    /** @param list<array{start:int,len:int,text:string,kind:string}> $out */
    private static function collect(string $text, string $re, string $kind, array &$out): void
    {
        if (preg_match_all($re, $text, $m, PREG_OFFSET_CAPTURE) === false) {
            return;
        }
        foreach ($m[0] as $hit) {
            $out[] = ['start' => $hit[1], 'len' => strlen($hit[0]), 'text' => $hit[0], 'kind' => $kind];
        }
    }

    /** @param array<string,true> $allowed @param list<string> $strings */
    private static function walk(mixed $v, array &$allowed, array &$strings): void
    {
        if (is_array($v)) {
            $list = array_is_list($v);
            foreach ($v as $k => $child) {
                if (!$list) {
                    self::addKeyDigits($allowed, (string) $k);
                }
                self::walk($child, $allowed, $strings);
            }
            return;
        }
        if (is_int($v)) {
            self::addInt($allowed, $v);
            return;
        }
        if (is_float($v) && is_finite($v) && floor($v) === $v && abs($v) < 1.0e15) {
            self::addInt($allowed, (int) $v);
            return;
        }
        if (is_string($v)) {
            $strings[] = $v;
            $tmp = [];
            self::collect($v, '/(?<![A-Za-z0-9_])(?<![.,])(\d{1,3}(?:,\d{3})+|\d+)(?![A-Za-z0-9_])(?![.,]\d)/', 'int', $tmp);
            foreach ($tmp as $m) {
                self::addInt($allowed, self::norm($m['text']));
            }
        }
    }

    /** @param array<string,true> $allowed */
    private static function addKeyDigits(array &$allowed, string $key): void
    {
        if (preg_match_all('/\d+/', $key, $m)) {
            foreach ($m[0] as $d) {
                self::addInt($allowed, self::norm($d));
            }
        }
    }

    /** @param array<string,true> $allowed */
    private static function addInt(array &$allowed, int|string $n): void
    {
        $allowed[self::norm((string) $n)] = true;
    }

    /** @param array<string,true> $allowed */
    private static function addClockParts(array &$allowed, string $rfc, DateTimeZone $display): void
    {
        try {
            $dt = new DateTimeImmutable($rfc);
        } catch (Throwable) {
            return;
        }
        foreach ([$dt->setTimezone(new DateTimeZone('UTC')), $dt->setTimezone($display)] as $z) {
            self::addInt($allowed, (int) $z->format('Y'));
            self::addInt($allowed, (int) $z->format('n'));
            self::addInt($allowed, (int) $z->format('j'));
            $hour = (int) $z->format('G');
            self::addInt($allowed, $hour);
            $h12 = $hour % 12;
            self::addInt($allowed, $h12 === 0 ? 12 : $h12);
            self::addInt($allowed, (int) $z->format('i'));
        }
    }

    private static function norm(string $digits): string
    {
        $digits = str_replace(',', '', $digits);
        $digits = ltrim($digits, '0');
        return $digits === '' ? '0' : $digits;
    }
}
