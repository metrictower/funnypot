<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Severity;
use Funnypot\Mainnet\Client;
use Funnypot\Mainnet\Config as MainnetConfig;
use Funnypot\Mainnet\Report\PdoSqliteReportQueue;
use Funnypot\Mainnet\Report\Reporter;
use Funnypot\Mainnet\Transport\CurlTransport;
use InvalidArgumentException;

/**
 * Batteries-included facade: funnypot-core detection wired to funnypot-mainnet-client reporting.
 *
 * The two packages already compose by hand. What this adds is the wiring an embedder would
 * otherwise have to rediscover, plus the invariants that are easy to get wrong:
 *
 *  - detect() is pure and cheap, so it is safe inline. report() only ever ENQUEUES; delivery
 *    happens in drain(), which the host must call out of band (cron, scheduler, worker). There
 *    is no genuinely async HTTP in stock PHP without an event loop, so the queue is the seam.
 *  - a bare template match is NOT a report signal. The nuclei corpus carries fingerprint
 *    templates next to exploit ones, so ordinary browser chatter (/favicon.ico, /robots.txt,
 *    /sitemap.xml, /manifest.json) matches. reportable() applies a severity floor — see the
 *    README for why a floor is a stopgap rather than the fix.
 *
 * It also refuses to start half-configured. The SDK is deliberately fail-safe and will skip
 * silently when a key, self_ips, or a queue path is missing; for an embedder that reads as
 * "installed and working" right up until nobody notices no reports ever arrived. This facade
 * turns each of those into a constructor error instead.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, no promotion/match/enums.
 */
final class Funnypot
{
    /** Conservative default: fewer reports, no benign browser chatter. */
    public const DEFAULT_MIN_SEVERITY = 'high';

    /** @var Honeypot */
    private $engine;

    /** @var Client */
    private $mainnet;

    /** @var Reporter owned directly so drain() is reachable — Client exposes no drain of its own */
    private $reporter;

    /** @var string one of the core severity strings */
    private $minSeverity;

    public function __construct(
        Honeypot $engine,
        Client $mainnet,
        Reporter $reporter,
        string $minSeverity = self::DEFAULT_MIN_SEVERITY
    ) {
        $this->engine = $engine;
        $this->mainnet = $mainnet;
        $this->reporter = $reporter;
        $this->minSeverity = $minSeverity;
    }

    /**
     * Build from a plain config array.
     *
     * Required keys: 'key', 'self_ips', 'intel_db_path'. Each is a silent-skip path in the SDK
     * if absent, so each is validated loudly here instead.
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
            Honeypot::default(),
            new Client($mainnetConfig, $transport, null, $reporter),
            $reporter,
            isset($config['min_severity']) ? (string) $config['min_severity'] : self::DEFAULT_MIN_SEVERITY
        );
    }

    /**
     * Classify a request. Pure, no I/O, safe inline on the request path.
     */
    public function inspect(RequestContext $r): Detection
    {
        return $this->engine->detect($r);
    }

    /**
     * Whether a detection clears the reporting floor.
     *
     * Severity-only, so coarse. An embedder wanting the composite decision (severity combined
     * with request-shape anomaly, which is what actually separates a scanner from a browser on
     * a boring path) should drive funnypot-policy instead of this method.
     */
    public function reportable(Detection $detection): bool
    {
        if (!$detection->matched || $detection->highestSeverity === '') {
            return false;
        }

        return Severity::rank($detection->highestSeverity) >= Severity::rank($this->minSeverity);
    }

    /**
     * Enqueue an abuse report. Never performs network I/O — delivery happens in drain().
     *
     * The caller supplies the IP: core is IP-blind, RequestContext carries no client address.
     *
     * @return array{queued:bool,reason:string}
     */
    public function report(string $ip, Detection $detection, string $comment = ''): array
    {
        if (!$this->reportable($detection)) {
            return array('queued' => false, 'reason' => 'below severity floor');
        }

        if ($comment === '') {
            $ids = $detection->templateIds();
            $comment = 'funnypot: ' . $detection->highestSeverity . ' ' . implode(',', array_slice($ids, 0, 5));
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
        return $this->engine;
    }

    public function mainnet(): Client
    {
        return $this->mainnet;
    }
}
