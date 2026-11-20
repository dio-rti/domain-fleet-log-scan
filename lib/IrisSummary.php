<?php
declare(strict_types=1);

namespace Fls;

/**
 * Optional Iris prose. Off unless --iris-summary is passed with --iris-publish.
 * Tests inject a runner. The real CLI is never required for the gates.
 */
final class IrisSummary
{
    public const MODEL = 'grok-4.7-high';
    public const PROMPT_LIMIT = 262144;

    private const PROMPT = <<<'PROMPT'
You are writing the summary of one read-only log scan for an operations lead.
Use ONLY the JSON document below. Do not use memory, other runs, or general knowledge.

Write plain English in exactly this order. Use these labels exactly:

1. A result paragraph that starts "The {{REGION_LABEL}} log scan is done." It gives:
   the number of sites and the site ids in scope.sites; "X of their Y servers were read"
   using result.roles_ok and result.roles_total; the engine from job.executor
   (say "Cursor only" only if job.executor is "cursor" or "cursor-agent"; otherwise name
   job.executor and job.model if set); the time as "{{LOCAL_DATE}}, {{LOCAL_START}} to
   {{LOCAL_END}} {{ZONE_NAME}}"; delivery from safety.delivery; every role with status
   "timeout" with error.limit_seconds; any coverage_gaps note copied word for word;
   then "Over the last N hours the scan found E errors and W warnings" from window.hours
   and totals. If window.hours is 0 or missing, write "The scan found E errors and
   W warnings." instead.
2. A line "What stands out:" followed by one "- " bullet per urgent[] row, in the order
   given in the document. Each bullet names the site and server role, gives each count from
   breakdown (breakdown maps site id to role name to count), names the error class from
   title or detail, and copies any pattern sentence from detail word for word.
3. A line starting "Quiet logs:" listing roles that have log_last_write_clock. If a time is
   not a full date-time with offset, say the report gives a clock time without a date or time
   zone, so the summary cannot say exactly when they stopped. If there are none, write
   "Quiet logs: none reported."
4. A line starting "Missing from this scan:" using totals.fatals and totals.http_500_bursts,
   then the sentence "The scan cannot see Apache 5xx errors."
5. One safety sentence from scope.mode, safety.server_writes, safety.sudo_used,
   safety.ipv4_in_outputs and safety.live_enabled_after_run.
6. "Most urgent: " plus the first urgent[] title, then the next fix copied from the
   suggested_fixes or coverage_gaps text that matches it.

Hard rules:
- Every count is written in digits, with commas for thousands (8,108). Never spell a count
  as a word. Never write a number that is not in the document or in the times given above.
  No percentages, averages, sums or estimates of your own.
- Every time includes the date and the zone name. Use only the times given above.
- No IP addresses, hostnames, email addresses, usernames, passwords, tokens, keys, or file
  paths. Do not start the text with "/". Never write "~/", "/Users/", "/home/", "/root/",
  "$HOME" or "%USERPROFILE%". Site-and-role forms such as "30000/db" are allowed when the
  document contains them.
- Do not compare with other runs, regions or days unless the document already contains that
  sentence. Never write "again", "this time", "as usual" or "by itself" unless those words
  are in the document. Mention another site id only if it appears in a document string.
- No headings, bold, links, tables, code or HTML. Paragraphs separated by one blank line;
  list items start with "- ".
- Do not mention yourself or the model. At most 3,000 characters.

Times to use:
- Scan: {{LOCAL_DATE}}, {{LOCAL_START}} to {{LOCAL_END}} {{ZONE_NAME}}
{{QUIET_TIMES_LINES}}

Document:
{{DOCUMENT_JSON}}
PROMPT;

    public static function enabled(array $opt): bool
    {
        return !empty($opt['iris_summary']) && !empty($opt['iris_publish']);
    }

    /** @return list<string> */
    public static function argv(string $prompt): array
    {
        return ['cursor-agent', '-p', '--model', self::MODEL, '--trust', '--force', '--mode', 'ask', '--output-format', 'text', $prompt];
    }

    /**
     * @param callable(array, string): array{exit:int,stdout:string,timedOut:bool}|null $runner
     * @return array{doc:array, reason:?string, argv:?array, cwd:?string}
     */
    public static function attach(array $doc, array $opt = []): array
    {
        $source = $doc;
        unset($source['ai_summary'], $source['payload_hash']);
        $prompt = self::prompt($source);
        $runner = $opt['runner'] ?? null;
        if (strlen($prompt) > self::PROMPT_LIMIT) {
            return self::skipped($doc, 'prompt-too-large', $opt);
        }
        if (self::tripwireInput($prompt) !== null) {
            return self::skipped($doc, 'tripwire', $opt);
        }
        if ($runner === null && self::resolveBin((string)($opt['bin'] ?? 'cursor-agent')) === null) {
            return self::skipped($doc, 'missing-cli', $opt);
        }
        $cwd = self::isolatedCwd();
        if ($cwd === null) {
            return self::skipped($doc, 'no-temp-dir', $opt);
        }
        $argv = self::argv($prompt);
        try {
            if ($runner !== null) {
                $ran = $runner($argv, $cwd);
            } else {
                $ran = Proc::run($argv, '', 180, $cwd);
            }
        } finally {
            self::removeIso($cwd);
        }
        $out = ['doc' => $doc, 'reason' => null, 'argv' => $argv, 'cwd' => $cwd];
        if (!empty($ran['timedOut'])) {
            return self::skipped($doc, 'timeout', $opt, $argv, $cwd);
        }
        if (($ran['exit'] ?? 1) !== 0) {
            return self::skipped($doc, 'model-unavailable', $opt, $argv, $cwd);
        }
        $text = trim((string)($ran['stdout'] ?? ''));
        if ($text === '') {
            return self::skipped($doc, 'empty', $opt, $argv, $cwd);
        }
        $why = IrisSummaryVerifier::rejectReason($text, $source);
        if ($why !== null) {
            return self::skipped($doc, $why, $opt, $argv, $cwd);
        }
        if (Redact::tripwire($text) !== null) {
            return self::skipped($doc, 'tripwire', $opt, $argv, $cwd);
        }
        $sealed = self::seal($doc, ['status' => 'ok', 'text' => $text, 'model' => self::MODEL], true);
        $out['doc'] = $sealed;
        return $out;
    }

    public static function prompt(array $source): string
    {
        unset($source['ai_summary'], $source['payload_hash']);
        $zone = SummaryNumberTrace::displayZone($source);
        $region = strtoupper((string)($source['scope']['region'] ?? ''));
        if (!preg_match('/^[A-Z]{2,8}$/', $region)) {
            $region = 'LOG';
        }
        $start = self::clock($source['timing']['started_at'] ?? '', $zone);
        $end = self::clock($source['timing']['finished_at'] ?? '', $zone);
        $repl = [
            '{{REGION_LABEL}}' => $region,
            '{{LOCAL_DATE}}' => $start['date'],
            '{{LOCAL_START}}' => $start['clock'],
            '{{LOCAL_END}}' => $end['clock'],
            '{{ZONE_NAME}}' => $zone->getName(),
            '{{QUIET_TIMES_LINES}}' => self::quietLines($source),
            '{{DOCUMENT_JSON}}' => json_encode($source, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ];
        return strtr(self::PROMPT, $repl);
    }

    /** @param array{exit?:int,stdout?:string,timedOut?:bool}|null $unused */
    private static function skipped(array $doc, string $reason, array $opt, ?array $argv = null, ?string $cwd = null): array
    {
        self::log(isset($opt['log']) ? (string)$opt['log'] : null, $reason);
        return [
            'doc' => self::seal($doc, ['status' => 'skipped', 'text' => null, 'model' => null], false),
            'reason' => $reason,
            'argv' => $argv,
            'cwd' => $cwd,
        ];
    }

    private static function seal(array $doc, array $ai, bool $used): array
    {
        $doc['ai_summary'] = $ai;
        if (!isset($doc['safety']) || !is_array($doc['safety'])) {
            $doc['safety'] = [];
        }
        $doc['safety']['summary_model_used'] = $used;
        unset($doc['payload_hash']);
        $doc['payload_hash'] = IrisPublish::hash($doc);
        return $doc;
    }

    /** Run ids and RFC3339 stamps are identity fields, not leaked counters. */
    private static function tripwireInput(string $prompt): ?string
    {
        $masked = str_replace('safety.live_enabled_after_run', 'safety live_enabled_after_run', $prompt);
        $masked = preg_replace('/\d{8}T\d{6}Z?-[0-9a-f]{4,12}/', '{run}', $masked) ?? $masked;
        $masked = preg_replace('/(?<=log-scan-)\d{8}/', '{day}', $masked) ?? $masked;
        $masked = preg_replace('/\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/', '{time}', $masked) ?? $masked;
        return Redact::tripwire($masked);
    }

    /** @return array{date:string,clock:string} */
    private static function clock(string $rfc, \DateTimeZone $zone): array
    {
        if (!SummaryNumberTrace::isRfc3339($rfc)) {
            return ['date' => 'unknown', 'clock' => 'unknown'];
        }
        try {
            $dt = (new \DateTimeImmutable($rfc))->setTimezone($zone);
        } catch (\Throwable) {
            return ['date' => 'unknown', 'clock' => 'unknown'];
        }
        return ['date' => $dt->format('j F Y'), 'clock' => $dt->format('H:i')];
    }

    private static function quietLines(array $source): string
    {
        $lines = [];
        foreach ($source['sites'] ?? [] as $site) {
            if (!is_array($site)) {
                continue;
            }
            foreach ($site['roles'] ?? [] as $role) {
                if (!is_array($role) || !isset($role['log_last_write_clock']) || !is_array($role['log_last_write_clock'])) {
                    continue;
                }
                $clock = $role['log_last_write_clock'];
                $time = $clock['time'] ?? '';
                $name = ($site['site_id'] ?? 'site') . ' ' . ($role['role'] ?? 'role');
                if (is_string($time) && SummaryNumberTrace::isRfc3339($time)) {
                    try {
                        $dt = new \DateTimeImmutable($time);
                    } catch (\Throwable) {
                        $lines[] = '- ' . $name . ' clock is not a full date-time';
                        continue;
                    }
                    $tz = is_string($clock['timezone'] ?? null) && $clock['timezone'] !== '' ? $clock['timezone'] : 'unknown';
                    $lines[] = '- ' . $name . ' at ' . $dt->format('H:i') . ' on ' . $dt->format('j F Y') . ' ' . $tz;
                } else {
                    $lines[] = '- ' . $name . ' clock is not a full date-time';
                }
            }
        }
        return $lines ? implode("\n", $lines) : '- none';
    }

    private static function resolveBin(string $bin): ?string
    {
        if ($bin !== '' && str_contains($bin, '/') && is_file($bin) && is_executable($bin)) {
            return $bin;
        }
        if ($bin === '' || str_contains($bin, '/')) {
            return null;
        }
        foreach (explode(PATH_SEPARATOR, (string)getenv('PATH')) as $dir) {
            $candidate = rtrim($dir, '/') . '/' . $bin;
            if (is_file($candidate) && is_executable($candidate)) {
                return $candidate;
            }
        }
        return null;
    }

    private static function isolatedCwd(): ?string
    {
        $base = realpath(sys_get_temp_dir());
        if ($base === false) {
            return null;
        }
        $dir = $base . '/fls-iris-' . bin2hex(random_bytes(8));
        if (!@mkdir($dir, 0700)) {
            return null;
        }
        $real = realpath($dir);
        if ($real === false || !str_starts_with($real, $base . '/') || !str_starts_with(basename($real), 'fls-iris-')) {
            if (is_dir($dir)) {
                @rmdir($dir);
            }
            return null;
        }
        $home = getenv('HOME');
        if (is_string($home) && $home !== '') {
            $root = realpath($home . '/.openclaw/workspace-abella');
            if ($root !== false && ($real === $root || str_starts_with($real, $root . '/'))) {
                @rmdir($real);
                return null;
            }
        }
        if (array_diff(scandir($real) ?: [], ['.', '..'])) {
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
        if (!str_starts_with(basename($real), 'fls-iris-')) {
            return;
        }
        Fs::rmTree($real);
    }

    private static function log(?string $path, string $reason): void
    {
        if ($path === null || $path === '' || !is_dir(dirname($path))) {
            return;
        }
        try {
            Fs::writeSecure($path, $reason . "\n");
        } catch (\Throwable) {
        }
    }
}
