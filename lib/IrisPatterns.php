<?php
declare(strict_types=1);

namespace Fls;

/** Fixed sentences for Iris detail, note and fix_text. Never used as a site id. */
final class IrisPatterns
{
    public static function match(?string $role, ?string $status, ?string $text): ?string
    {
        if ($role === 'db' && $status === 'timeout') {
            return 'Same problem as 30000/db.';
        }
        $text ??= '';
        if (str_contains($text, 'Required server command failed') && (str_contains($text, 'lock') || str_contains($text, 'cache'))) {
            return 'Same pattern as 30010 on VERTEX.';
        }
        return null;
    }
}
