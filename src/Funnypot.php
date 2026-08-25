<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Verdict;
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

    /** @var Honeypot */
    private $engine;

    /** @var Client */
    private $mainnet;

    /** @var Reporter owned directly so drain() is reachable — Client exposes no drain of its own */
    private $reporter;

    /** @var SiteProfile the host's real-route oracle */
    private $profile;

    /** @var string one of the PROFILE_* constants */
    private $posture;

    /** @var array<string,true> */
    private $ambient;

    /** @var Judge|null */
    private $judge;

    /**
     * @param array<string,true> $ambient
     */
    public function __construct(
        Honeypot $engine,
        Client $mainnet,
        Reporter $reporter,
        SiteProfile $profile,
        string $posture = self::PROFILE_APP,
        array $ambient = array(),
        ?Judge $judge = null
    ) {
        $this->engine = $engine;
        $this->mainnet = $mainnet;
        $this->reporter = $reporter;
        $this->profile = $profile;
        $this->posture = $posture;
        $this->ambient = $ambient === array() ? AmbientPaths::lookup() : $ambient;
        $this->judge = $judge;
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

        if (isset($config['min_severity'])) {
            throw new InvalidArgumentException(
                'funnypot: "min_severity" no longer exists. There is no severity axis to set — at the '
                . 'old default of "high" a real browser was reportable on your own /, /login and '
                . '/index.php, all of which the corpus rates critical. Use "profile" instead.'
            );
        }

        $posture = isset($config['profile']) ? (string) $config['profile'] : self::PROFILE_APP;
        if ($posture !== self::PROFILE_APP && $posture !== self::PROFILE_HONEYPOT) {
            throw new InvalidArgumentException(
                'funnypot: "profile" must be Funnypot::PROFILE_APP or Funnypot::PROFILE_HONEYPOT.'
            );
        }

        $profile = self::buildSiteProfile($config, $posture);

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

        $judge = isset($config['judge']) ? $config['judge'] : null;
        if ($judge !== null && !$judge instanceof Judge) {
            throw new InvalidArgumentException('funnypot: "judge" must implement Funnypot\Sensor\Judge.');
        }

        return new self(
            Honeypot::default(),
            new Client($mainnetConfig, $transport, null, $reporter),
            $reporter,
            $profile,
            $posture,
            AmbientPaths::lookup(
                isset($config['ambient_extra']) && is_array($config['ambient_extra']) ? $config['ambient_extra'] : array(),
                isset($config['ambient_drop']) && is_array($config['ambient_drop']) ? $config['ambient_drop'] : array()
            ),
            $judge
        );
    }

    /**
     * The real-route oracle, required under PROFILE_APP for the same reason the key is: without
     * it the package silently does the wrong thing.
     *
     * /login, /admin, /register and /index.php are all in the nuclei corpus — scanners look for
     * them precisely BECAUSE real apps have them — so core cannot know yours are genuine unless
     * you say so. Measured before this was required: a real Chrome browser was reportable on 8
     * of 10 ordinary application routes.
     *
     * Under PROFILE_HONEYPOT the question does not arise: nothing on the host is real.
     *
     * @param array<string,mixed> $config
     */
    private static function buildSiteProfile(array $config, string $posture): SiteProfile
    {
        $stack = array(isset($config['stack']) ? (string) $config['stack'] : 'unknown');
        $noRoutes = static function ($method, $path) {
            return false;
        };

        if ($posture === self::PROFILE_HONEYPOT) {
            return new SiteProfile($stack, $noRoutes);
        }

        if (!array_key_exists('own_routes', $config)) {
            throw new InvalidArgumentException(
                'funnypot: "own_routes" is required — a callable fn(string $method, string $path): bool '
                . 'saying whether a path is a REAL route on this site. Without it your own /login and '
                . '/admin look exactly like scanner probes and your real visitors get reported. '
                . 'Pass Funnypot::ONLY_ON_404 if you only call check() from your 404 handler.'
            );
        }

        if ($config['own_routes'] === self::ONLY_ON_404) {
            return new SiteProfile($stack, $noRoutes);
        }

        if (!is_callable($config['own_routes'])) {
            throw new InvalidArgumentException(
                'funnypot: "own_routes" must be a callable fn($method, $path): bool, or '
                . 'Funnypot::ONLY_ON_404.'
            );
        }

        $routes = $config['own_routes'];

        return new SiteProfile($stack, static function ($method, $path) use ($routes) {
            return (bool) call_user_func($routes, $method, $path);
        });
    }

    /**
     * Classify a request and decide what to do about it. Pure, no I/O, safe inline.
     *
     * Uses classify(), NOT detect(). detect() projects the Verdict down to its Detection and
     * throws the classification away, so core would conclude CLEAN while the Detection still
     * read matched=true at critical severity.
     */
    public function check(RequestContext $r): Assessment
    {
        $verdict = $this->engine->classify($r, $this->profile);
        $kind = $this->kindOf($verdict, $r);

        if ($this->judge !== null) {
            $ruling = $this->judge->judge($verdict, $r, $this->posture);

            return new Assessment(
                $verdict,
                $kind,
                (bool) $ruling['report'],
                (bool) $ruling['block'],
                isset($ruling['reason']) ? (string) $ruling['reason'] : 'judge'
            );
        }

        return $this->rule($verdict, $kind);
    }

    /**
     * Ambient is a property of the PATH, checked only once core has already said "corpus hit".
     * A clean request stays clean, and a request core rates attack-class is never softened by
     * the path it came in on.
     */
    private function kindOf(Verdict $verdict, RequestContext $r): string
    {
        if ($verdict->classification !== Verdict::SCANNER_PROBE) {
            return $verdict->classification;
        }

        $path = $r->path;
        $query = strpos($path, '?');
        if ($query !== false) {
            $path = substr($path, 0, $query);
        }

        return isset($this->ambient[$path]) ? Assessment::AMBIENT : $verdict->classification;
    }

    /**
     * The default judgement. A named flag, never a number.
     *
     * The anomaly bands interleave — UptimeRobot 24, Googlebot 19, curl 14 — so no threshold
     * separates a scanner from a monitor. SCANNER_USER_AGENT fires for the scanner UA class and
     * for none of those legitimate clients.
     *
     * shouldBlock() covers scanner-probe as well as attack-class. Core reaches attack-class only
     * with attack emulation on, which is a response-SERVING feature: measured, it changes no
     * classification at all and costs ~20x on the miss path, so a detection sensor leaves it off.
     * Blocking is safe here because the two ways a real visitor could reach this branch are both
     * already closed — a real route is fenced by the oracle, and browser chatter is ambient.
     */
    private function rule(Verdict $verdict, string $kind): Assessment
    {
        $honeypot = $this->posture === self::PROFILE_HONEYPOT;

        if ($kind === Verdict::CLEAN || $kind === Verdict::SUSPICIOUS) {
            return new Assessment($verdict, $kind, false, false, 'clean');
        }

        // Ambient paths are never blocked, even from a scanner. Refusing a /robots.txt fetch
        // gains nothing and costs you a crawler the day the UA match is wrong.
        if ($kind === Assessment::AMBIENT) {
            if ($honeypot) {
                return new Assessment($verdict, $kind, true, false, 'honeypot-profile');
            }

            $scannerUa = $verdict->signals->has(BotSignalSet::SCANNER_USER_AGENT);

            return new Assessment($verdict, $kind, $scannerUa, false, $scannerUa ? 'scanner-ua' : 'ambient');
        }

        // A honeypot that blocks has told the attacker it detected them.
        $reason = $honeypot ? 'honeypot-profile' : ($kind === Verdict::ATTACK_CLASS ? 'attack' : 'probe');

        return new Assessment($verdict, $kind, true, !$honeypot, $reason);
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
        return $this->engine;
    }

    public function mainnet(): Client
    {
        return $this->mainnet;
    }
}
