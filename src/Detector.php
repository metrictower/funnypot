<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\Config as CoreConfig;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Verdict;
use InvalidArgumentException;

/**
 * The judgement, with no reporting attached.
 *
 * Use this when the host already has a queue. Mainnet delivery in Funnypot rides a bundled SQLite
 * queue, which is the right default for a framework-free app and the wrong one for a Laravel or
 * Symfony host: N workers on an ephemeral container filesystem would fragment the dedup state and
 * the daily counter per worker and lose both on redeploy. Such a host wants check() here and its
 * own job for delivery.
 *
 * check() is pure — no I/O, no state — so this needs no mainnet key and no queue path.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, no promotion/match/enums.
 */
final class Detector
{
    /** @var Honeypot */
    private $engine;

    /** @var SiteProfile */
    private $profile;

    /** @var string one of Funnypot's PROFILE_* constants */
    private $posture;

    /** @var array<string,true> */
    private $ambient;

    /** @var Judge|null */
    private $judge;

    /** @var bool opt-in: may a scripting UA (curl, python-requests) raise a report on its own? */
    private $actOnScriptingUas;

    /**
     * @param array<string,true> $ambient
     */
    public function __construct(
        Honeypot $engine,
        SiteProfile $profile,
        string $posture = Funnypot::PROFILE_APP,
        array $ambient = array(),
        ?Judge $judge = null,
        bool $actOnScriptingUas = false
    ) {
        $this->engine = $engine;
        $this->profile = $profile;
        $this->posture = $posture;
        $this->ambient = $ambient === array() ? AmbientPaths::lookup() : $ambient;
        $this->judge = $judge;
        $this->actOnScriptingUas = $actOnScriptingUas;
    }

    /**
     * Build from a plain config array. Accepts the same detection keys Funnypot::fromArray() does
     * — 'profile', 'own_routes', 'stack', 'ambient_extra', 'ambient_drop', 'ignore_templates',
     * 'judge' — and none of the reporting ones.
     *
     * @param array<string,mixed> $config
     */
    public static function fromArray(array $config): self
    {
        if (isset($config['min_severity'])) {
            throw new InvalidArgumentException(
                'funnypot: "min_severity" no longer exists. There is no severity axis to set — at the '
                . 'old default of "high" a real browser was reportable on your own /, /login and '
                . '/index.php, all of which the corpus rates critical. Use "profile" instead.'
            );
        }

        $posture = isset($config['profile']) ? (string) $config['profile'] : Funnypot::PROFILE_APP;
        if ($posture !== Funnypot::PROFILE_APP && $posture !== Funnypot::PROFILE_HONEYPOT) {
            throw new InvalidArgumentException(
                'funnypot: "profile" must be Funnypot::PROFILE_APP or Funnypot::PROFILE_HONEYPOT.'
            );
        }

        $judge = isset($config['judge']) ? $config['judge'] : null;
        if ($judge !== null && !$judge instanceof Judge) {
            throw new InvalidArgumentException('funnypot: "judge" must implement Funnypot\Sensor\Judge.');
        }

        return new self(
            Honeypot::default(self::coreConfig($config)),
            self::buildSiteProfile($config, $posture),
            $posture,
            AmbientPaths::lookup(
                isset($config['ambient_extra']) && is_array($config['ambient_extra']) ? $config['ambient_extra'] : array(),
                isset($config['ambient_drop']) && is_array($config['ambient_drop']) ? $config['ambient_drop'] : array()
            ),
            $judge,
            isset($config['act_on_scripting_uas']) && $config['act_on_scripting_uas'] === true
        );
    }

    /**
     * The real-route oracle, required under PROFILE_APP for the same reason the mainnet key is:
     * without it the package silently does the wrong thing.
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
    public static function buildSiteProfile(array $config, string $posture): SiteProfile
    {
        $stack = array(isset($config['stack']) ? (string) $config['stack'] : 'unknown');
        $noRoutes = static function ($method, $path) {
            return false;
        };

        if ($posture === Funnypot::PROFILE_HONEYPOT) {
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

        if ($config['own_routes'] === Funnypot::ONLY_ON_404) {
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
     * The core Config the sensor drives the engine with. The sensor is detection-only, so this is
     * core's inert default plus the one detection knob it exposes: 'ignore_templates'.
     *
     * 'ignore_templates' silences templates on the DETECTION side — a request whose only matching
     * templates are listed classifies clean and is never reported. It accepts template ids AND tags;
     * find the id to list by reading Assessment::templateIds() off a false-positive report. It is a
     * per-deployment property (a template noisy on this site is noisy on every call site), so it is
     * config here, never a call-site argument. It is NOT core's 'exclude', which governs SERVING and
     * has no meaning for a detection sensor.
     *
     * @param array<string,mixed> $config
     */
    private static function coreConfig(array $config): CoreConfig
    {
        $ignore = array();
        if (isset($config['ignore_templates'])) {
            if (!is_array($config['ignore_templates'])) {
                throw new InvalidArgumentException(
                    'funnypot: "ignore_templates" must be an array of template ids or tags to exclude '
                    . 'from detection. Read the id to list off a false-positive report with '
                    . 'Assessment::templateIds().'
                );
            }
            $ignore = array_values(array_map('strval', $config['ignore_templates']));
        }

        $core = new CoreConfig();
        $core->ignoreTemplates = $ignore;

        return $core;
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
        $path = self::stripQuery($r->path);
        $kind = $this->kindOf($verdict, $path);

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

        return $this->rule($verdict, $kind, $path);
    }

    public function engine(): Honeypot
    {
        return $this->engine;
    }

    private static function stripQuery(string $path): string
    {
        $query = strpos($path, '?');

        return $query === false ? $path : substr($path, 0, $query);
    }

    /**
     * Ambient is a property of the PATH, checked only once core has already said "corpus hit".
     * A clean request stays clean, and a request core rates attack-class is never softened by
     * the path it came in on.
     */
    private function kindOf(Verdict $verdict, string $path): string
    {
        if ($verdict->classification !== Verdict::SCANNER_PROBE) {
            return $verdict->classification;
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
     *
     * /robots.txt is exempt from PROFILE_HONEYPOT's blanket ambient reporting (operator decision,
     * 2026-08-25): a well-behaved crawler is expected to fetch it even on a box with nothing real
     * behind it, and reporting compliant behaviour earns nothing. Scoped to PROFILE_HONEYPOT only
     * — under PROFILE_APP, ambient reporting already requires SCANNER_USER_AGENT, which targets
     * known scanner tooling rather than honest crawler UAs, so there is no equivalent gap to close.
     */
    private function rule(Verdict $verdict, string $kind, string $path): Assessment
    {
        $honeypot = $this->posture === Funnypot::PROFILE_HONEYPOT;

        if ($kind === Verdict::CLEAN || $kind === Verdict::SUSPICIOUS) {
            return new Assessment($verdict, $kind, false, false, 'clean');
        }

        // Ambient paths are never blocked, even from a scanner. Refusing a /robots.txt fetch
        // gains nothing and costs you a crawler the day the UA match is wrong.
        if ($kind === Assessment::AMBIENT) {
            if ($honeypot) {
                if ($path === '/robots.txt') {
                    return new Assessment($verdict, $kind, false, false, 'robots-exempt');
                }

                return new Assessment($verdict, $kind, true, false, 'honeypot-profile');
            }

            // A NAMED scanner tool is worth a report even on a path everyone is asked for.
            if ($verdict->signals->has(BotSignalSet::SCANNER_USER_AGENT)) {
                return new Assessment($verdict, $kind, true, false, 'scanner-ua');
            }

            // A scripting UA is NOT, unless the host opts in. curl and python-requests against an
            // API are the expected clients, so acting on them by default would report the
            // integrations the app exists to serve. Reporting only — never blocking.
            if ($this->actOnScriptingUas && $verdict->signals->uaClass === BotSignalSet::UA_SCRIPT) {
                return new Assessment($verdict, $kind, true, false, 'scripting-ua');
            }

            return new Assessment($verdict, $kind, false, false, 'ambient');
        }

        // A honeypot that blocks has told the attacker it detected them.
        $reason = $honeypot ? 'honeypot-profile' : ($kind === Verdict::ATTACK_CLASS ? 'attack' : 'probe');

        return new Assessment($verdict, $kind, true, !$honeypot, $reason);
    }
}
