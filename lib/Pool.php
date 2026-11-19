<?php
declare(strict_types=1);

namespace Fls;

/**
 * proc_open pool, one queue per physical jump lane. Cap per lane, start stagger per lane,
 * total timeout, no retries, circuit breaker on "connection reset by peer" (pauses the lane:
 * running sessions finish, queued ones are skipped and reported).
 * Raw stderr is classified and dropped; it is never returned (it can contain addresses).
 */
final class Pool
{
    public array $starts = [];      // lane => [float start times]
    public array $maxRunning = [];  // lane => observed max concurrency
    public array $breaker = [];     // lane => true when tripped
    public int $spawned = 0;

    public function __construct(
        private int $cap,
        private float $stagger,
        private float $totalTimeout,
        private int $outputCap = 4194304,
    ) {}

    public static function classify(string $stderr, int $exit, bool $timedOut): string
    {
        if ($timedOut) {
            return 'timeout';
        }
        $e = strtolower($stderr);
        return match (true) {
            str_contains($e, 'connection reset by peer') => 'reset',
            str_contains($e, 'host key verification failed'), str_contains($e, 'remote host identification has changed') => 'hostkey',
            str_contains($e, 'password:'), str_contains($e, 'passphrase'), str_contains($e, 'verification code') => 'prompt',
            str_contains($e, 'permission denied') => 'auth',
            str_contains($e, 'timed out') => 'timeout',
            str_contains($e, 'could not resolve'), str_contains($e, 'no route to host'), str_contains($e, 'connection refused'), str_contains($e, 'network is unreachable'), str_contains($e, 'connection closed') => 'unreachable',
            $exit === 0 => 'ok',
            $exit === 255 => 'unreachable',
            default => 'error',
        };
    }

    /**
     * @param array<int,array{id:string,lane:string,argv:array,stdin:string,env?:array}> $jobs
     * @return array<string,array{status:string,exit:int,stdout:string,duration:float}>
     */
    public function run(array $jobs): array
    {
        $queues = [];
        foreach ($jobs as $j) {
            $queues[$j['lane']][] = $j;
        }
        $running = [];      // key => [job, proc, pipes, start, out, err]
        $results = [];
        $lastStart = [];
        $runningCount = [];
        while ($queues || $running) {
            $now = microtime(true);
            foreach ($queues as $lane => &$q) {
                if (!empty($this->breaker[$lane])) {
                    foreach ($q as $j) {
                        $results[$j['id']] = ['status' => 'skipped-breaker', 'exit' => -1, 'stdout' => '', 'duration' => 0.0];
                    }
                    $q = [];
                    continue;
                }
                $rc = $runningCount[$lane] ?? 0;
                if ($q && $rc < $this->cap && ($now - ($lastStart[$lane] ?? -INF)) >= $this->stagger) {
                    $j = array_shift($q);
                    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
                    $p = @proc_open($j['argv'], $spec, $pipes, null, $j['env'] ?? null);
                    $lastStart[$lane] = $now;
                    $this->starts[$lane][] = $now;
                    $this->spawned++;
                    if (!is_resource($p)) {
                        $results[$j['id']] = ['status' => 'error', 'exit' => 127, 'stdout' => '', 'duration' => 0.0];
                        continue;
                    }
                    @fwrite($pipes[0], $j['stdin']);
                    fclose($pipes[0]);
                    stream_set_blocking($pipes[1], false);
                    stream_set_blocking($pipes[2], false);
                    $running[$j['id']] = ['job' => $j, 'p' => $p, 'pipes' => $pipes, 'start' => $now, 'out' => '', 'err' => ''];
                    $runningCount[$lane] = $rc + 1;
                    $this->maxRunning[$lane] = max($this->maxRunning[$lane] ?? 0, $runningCount[$lane]);
                }
            }
            unset($q);
            $queues = array_filter($queues);
            if (!$running) {
                if ($queues) {
                    usleep(20000);
                }
                continue;
            }
            $r = [];
            foreach ($running as $s) {
                $r[] = $s['pipes'][1];
                $r[] = $s['pipes'][2];
            }
            $w = $e = null;
            @stream_select($r, $w, $e, 0, 50000);
            $done = [];
            foreach ($running as $id => &$s) {
                $s['out'] .= (string)@fread($s['pipes'][1], 65536);
                $s['err'] .= (string)@fread($s['pipes'][2], 65536);
                if (strlen($s['err']) > 65536) {
                    $s['err'] = substr($s['err'], -65536);
                }
                $st = proc_get_status($s['p']);
                $timedOut = (microtime(true) - $s['start']) > $this->totalTimeout;
                $oversize = strlen($s['out']) > $this->outputCap;
                if ($st['running'] && !$timedOut && !$oversize) {
                    continue;
                }
                if ($st['running']) {
                    proc_terminate($s['p'], 15);
                    usleep(200000);
                    if (proc_get_status($s['p'])['running']) {
                        proc_terminate($s['p'], 9);
                    }
                    $exit = 124;
                } else {
                    $s['out'] .= (string)stream_get_contents($s['pipes'][1]);
                    $s['err'] .= (string)stream_get_contents($s['pipes'][2]);
                    $exit = (int)$st['exitcode'];
                }
                fclose($s['pipes'][1]);
                fclose($s['pipes'][2]);
                proc_close($s['p']);
                $lane = $s['job']['lane'];
                $status = $oversize ? 'oversize' : self::classify($s['err'], $exit, $timedOut && !$oversize);
                if ($status === 'reset') {
                    $this->breaker[$lane] = true;
                }
                $results[$id] = [
                    'status' => $status,
                    'exit' => $exit,
                    'stdout' => $status === 'ok' ? $s['out'] : '',
                    'duration' => microtime(true) - $s['start'],
                ];
                $runningCount[$lane]--;
                $done[] = $id;
            }
            unset($s);
            foreach ($done as $id) {
                unset($running[$id]);
            }
        }
        return $results;
    }
}
