<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Mainnet\Client;
use Funnypot\Mainnet\Config as MainnetConfig;
use Funnypot\Mainnet\Report\PdoSqliteReportQueue;
use Funnypot\Mainnet\Report\Reporter;
use Funnypot\Mainnet\Transport\CurlTransport;
use InvalidArgumentException;

/**
 * Batteries-included facade: funnypot-core detection wired to funnypot-mainnet-client reporting.
 *
 * The whole integration is two questions:
 *
 *     $check = $funnypot->check($request);
 *     if ($check->shouldReport()) { $funnypot->report($clientIp, $check); }
 *     if ($check->shouldBlock())  { http_response_code(403); exit; }
 *
 * check() is pure and cheap, so it is safe inline. report() only ever ENQUEUES; delivery happens
 * in drain(), which the host calls out of band (cron, scheduler, worker). There is no genuinely
 * async HTTP in stock PHP without an event loop, so the queue is the seam.
 *
 * There is no severity floor and no anomaly threshold, because neither works. Severity is
 * ANTI-correlated with benignness at the top of the traffic distribution — the corpus piles its
 * most and most-severe templates onto `/`, `/index.php` and `/login`, since those are what
 * scanners look for — and anomaly is path-blind, scoring a client the same on /robots.txt as on
 * /.env, with UptimeRobot (24) and Googlebot (19) both above curl (14). The judgement turns on
 * the path property and named signal flags instead. See README.
 *
 * It also refuses to start half-configured. The SDK is deliberately fail-safe and will skip
 * silently when a key, self_ips, or a queue path is missing; for an embedder that reads as
 * "installed and working" right up until nobody notices no reports ever arrived.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, no promotion/match/enums.
 */
final class Funnypot
{
    /** A real site with real visitors. The default, and the safe one. */
    public const PROFILE_APP = 'app';

    /** No legitimate traffic reaches this host, so everything is worth reporting. */
    public const PROFILE_HONEYPOT = 'honeypot';

    /**
     * own_routes value for the documented mount point: check() runs inside the 404 / NotFound
     * handler, so the framework has already ruled that nothing here is a real route.
     */
    public const ONLY_ON_404 = 'only-on-404';

    /** @var Client */
    private $mainnet;

    /** @var Reporter owned directly so drain() is reachable — Client exposes no drain of its own */
    private $reporter;

    /** @var Detector the judgement half; pure, and usable on its own */
    private $detector;

    public function __construct(
        Detector $detector,
        Client $mainnet,
        Reporter $reporter
    ) {
        $this->detector = $detector;
        $this->mainnet = $mainnet;
        $this->reporter = $reporter;
    }

    /**
     * Build from a plain config array.
     *
     * Required: 'key', 'self_ips', 'intel_db_path', and — under PROFILE_APP — 'own_routes'.
     * Each is a silent-skip path somewhere downstream, so each is validated loudly here.
     *
     * @param array<string,mixed> $config
     */
    public static function fromArray(array $config): self
    {
        $key = isset($config['key']) ? (string) $config['key'] : '';
        if ($key === '') {
            throw new InvalidArgumentException(
                'funnypot: "key" is required — without a mainnet sensor key every report is dropped.'
            );
        }

        $selfIps = isset($config['self_ips']) && is_array($config['self_ips'])
            ? array_values($config['self_ips'])
            : array();
        if ($selfIps === array()) {
            throw new InvalidArgumentException(
                'funnypot: "self_ips" is required — the reporter refuses to report anything until it '
                . 'knows which addresses are your own. List this host\'s public addresses.'
            );
        }

        $dbPath = isset($config['intel_db_path']) ? (string) $config['intel_db_path'] : '';
        if ($dbPath === '') {
            throw new InvalidArgumentException(
                'funnypot: "intel_db_path" is required — it backs the report queue.'
            );
        }
        if (!extension_loaded('pdo_sqlite')) {
            throw new InvalidArgumentException(
                'funnypot: ext-pdo_sqlite is required for the bundled report queue. Install it, or '
                . 'construct Funnypot yourself with a Reporter carrying your own ReportQueue.'
            );
        }

        $detector = Detector::fromArray($config);

        $mainnetConfig = MainnetConfig::fromArray($config);
        $transport = new CurlTransport($mainnetConfig->timeoutMs());

        $reporter = new Reporter(
            new PdoSqliteReportQueue($dbPath),
            $transport,
            $mainnetConfig->baseUrl(),
            $mainnetConfig->key(),
            $mainnetConfig->selfIps(),
            $mainnetConfig->dailyCap(),
            $mainnetConfig->dedupHours()
        );

        return new self(
            $detector,
            new Client($mainnetConfig, $transport, null, $reporter),
            $reporter
        );
    }

    /**
     * Classify a request and decide what to do about it. Pure, no I/O, safe inline.
     */
    public function check(RequestContext $r): Assessment
    {
        return $this->detector->check($r);
    }

    /**
     * Enqueue an abuse report. Never performs network I/O — delivery happens in drain().
     *
     * The caller supplies the IP: core is IP-blind, RequestContext carries no client address.
     *
     * @return array{queued:bool,reason:string}
     */
    public function report(string $ip, Assessment $assessment, string $comment = ''): array
    {
        if (!$assessment->shouldReport()) {
            return array('queued' => false, 'reason' => $assessment->reason());
        }

        if ($comment === '') {
            $ids = $assessment->templateIds();
            $comment = 'funnypot: ' . $assessment->kind()
                . ($ids === array() ? '' : ' ' . implode(',', array_slice($ids, 0, 5)));
        }

        return $this->mainnet->report($ip, $comment);
    }

    /**
     * Deliver queued reports. Call OUT OF BAND — cron, scheduler tick, worker. Never on the
     * request path: it opens sockets.
     *
     * @return array<string,mixed>
     */
    public function drain(int $limit = 200): array
    {
        return $this->reporter->drain($limit);
    }

    public function queuedCount(): int
    {
        return (int) $this->reporter->queueCount();
    }

    public function engine(): Honeypot
    {
        return $this->detector->engine();
    }

    /** The judgement half on its own — what a host with its own queue wants. */
    public function detector(): Detector
    {
        return $this->detector;
    }

    public function mainnet(): Client
    {
        return $this->mainnet;
    }
}
