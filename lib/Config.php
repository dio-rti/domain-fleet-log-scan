<?php
declare(strict_types=1);

namespace Fls;

final class Config
{
    public const MODEL_NAME = 'grok-4.7-xhigh-fast';

    public static function load(string $file, string $toolDir): array
    {
        if (!is_file($file)) {
            throw new FlsException('config not found: ' . basename($file));
        }
        $c = require $file;
        if (!is_array($c)) {
            throw new FlsException('config must return an array');
        }
        $home = (string)getenv('HOME');
        $d = [
            'data_dir' => $toolDir,
            'tool_dir' => $toolDir,
            'sites' => ['include' => [], 'exclude' => []],
            'regions' => ['10' => 'jp', '11' => 'sg', '30' => 'vertex'],
            'jumps' => ['jp' => 'rti-jump-jp', 'sg' => 'rti-jump-sg', 'vertex' => 'rti-jump-vertex'],
            'lanes' => ['jp' => ['jp'], 'sgv' => ['sg', 'vertex']],
            'ssh_user' => 'wwkker',
            'ssh_bin' => '/usr/bin/ssh',
            'lane_cap' => 4,
            'stagger_s' => 2.5,
            'timeouts' => ['connect' => 15, 'total' => 120],
            'max_bytes_per_file' => 50 * 1024 * 1024,
            'first_run_hours' => 24,
            'live' => ['enabled' => false],
            'global_cli' => ['enabled' => true, 'bin' => $home . '/.local/bin/global', 'profiles' => ['jp' => 'jp', 'sg' => 'sg', 'vertex' => 'vertex'], 'timeout' => 30],
            'model' => ['enabled' => false, 'name' => self::MODEL_NAME, 'bin' => $home . '/.local/bin/cursor-agent', 'cwd' => $home . '/.openclaw/workspace-abella', 'timeout' => 90],
            'delivery' => ['openclaw' => ['enabled' => false, 'argv' => []]],
            'webhook_env' => $toolDir . '/webhook.env',
            'diff' => ['spike_factor' => 3.0, 'spike_min_count' => 20, 'history_days' => 8, 'median_days' => 7, 'warm_days' => 3],
            'trace' => ['max_entries' => 20, 'max_bytes' => 65536, 'default_days' => 7],
        ];
        $c = array_replace_recursive($d, $c);
        // lists are replaced, not merged
        foreach (['include', 'exclude'] as $k) {
            $c['sites'][$k] = array_values(array_map('strval', (array)($c['sites'][$k] ?? [])));
        }
        self::validate($c);
        return $c;
    }

    public static function validate(array $c): void
    {
        foreach (array_merge($c['sites']['include'], $c['sites']['exclude']) as $s) {
            if (!preg_match('/^\d{5}$/', $s)) {
                throw new FlsException('site ids must be 5 digits');
            }
        }
        if ((int)$c['lane_cap'] < 1 || (int)$c['lane_cap'] > 4) {
            throw new FlsException('lane_cap must be 1..4');
        }
        if ((float)$c['stagger_s'] < 2.5) {
            throw new FlsException('stagger_s must be >= 2.5');
        }
        if ((int)$c['timeouts']['connect'] < 1 || (int)$c['timeouts']['connect'] > 15 || (int)$c['timeouts']['total'] < 1 || (int)$c['timeouts']['total'] > 120) {
            throw new FlsException('timeouts must be connect<=15 total<=120');
        }
        if ($c['ssh_user'] !== 'wwkker') {
            throw new FlsException('ssh_user must be wwkker');
        }
        foreach ($c['jumps'] as $r => $alias) {
            if (!preg_match('/^rti-jump-[a-z]+$/', (string)$alias)) {
                throw new FlsException('jump entries must be rti-jump-* aliases');
            }
        }
        // SG and VERTEX are one physical jump. laneOf() returns the region name
        // when that region is missing from lanes, which would apply lane_cap twice.
        if (self::laneOf($c, 'sg') !== self::laneOf($c, 'vertex')) {
            throw new FlsException('sg and vertex must share one lane');
        }
        self::modelName($c);
    }

    /** The only model allowed for the optional summary. Anything else is a config error. */
    public static function modelName(array $c): string
    {
        $n = $c['model']['name'] ?? null;
        if ($n !== self::MODEL_NAME) {
            throw new FlsException('model.name must be exactly ' . self::MODEL_NAME);
        }
        return $n;
    }

    public static function regionOf(array $c, string $site): ?string
    {
        return $c['regions'][substr($site, 0, 2)] ?? null;
    }

    public static function laneOf(array $c, string $region): string
    {
        foreach ($c['lanes'] as $lane => $regions) {
            if (in_array($region, $regions, true)) {
                return $lane;
            }
        }
        return $region;
    }
}
