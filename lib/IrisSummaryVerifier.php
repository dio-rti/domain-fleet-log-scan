<?php
declare(strict_types=1);

namespace Fls;

/** Local gate before an Iris summary is attached. Iris remains the authority. */
final class IrisSummaryVerifier
{
    public static function rejectReason(string $text, array $doc): ?string
    {
        $text = trim($text);
        if ($text === '') {
            return 'empty';
        }
        if (strlen($text) > 8000) {
            return 'too-long';
        }
        if (str_contains($text, '<') || str_contains($text, '`') || str_contains($text, '](')) {
            return 'markup';
        }
        foreach (preg_split("/\r\n|\n|\r/", $text) ?: [] as $line) {
            if (str_starts_with(ltrim($line), '#')) {
                return 'markup';
            }
        }
        foreach (['What stands out:', 'Quiet logs:', 'Missing from this scan:', 'Most urgent:'] as $label) {
            if (!str_contains($text, $label)) {
                return 'labels';
            }
        }
        if (preg_match('/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/', $text)) {
            return 'ipv4';
        }
        if (preg_match_all('/[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*(?![A-Za-z0-9])/i', $text, $mm)) {
            foreach ($mm[0] as $tok) {
                if (Redact::isIpv6Token($tok)) {
                    return 'ipv6';
                }
            }
        }
        if (str_starts_with($text, '/')) {
            return 'path';
        }
        foreach (['~/', '/Users/', '/home/', '/root/', '$HOME', '%USERPROFILE%'] as $prefix) {
            if (str_contains($text, $prefix)) {
                return 'path';
            }
        }
        if (preg_match('/[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}/i', $text)) {
            return 'email';
        }
        if (preg_match('/\d{7,}/', $text)) {
            return 'long-digits';
        }
        if (SummaryNumberTrace::firstUntraced($text, $doc) !== null) {
            return 'summary_untraced';
        }
        return null;
    }
}
