<?php

declare(strict_types=1);

namespace Funnypot\Sensor\Policy;

use Funnypot\Core\Contracts\Evaluator as CoreEvaluatorContract;
use Funnypot\Policy\BotSignals as PolicyBotSignals;
use Funnypot\Policy\FakeResponse as PolicyFakeResponse;
use Funnypot\Policy\Port\EvaluatorInterface;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\SiteProfile as PolicySiteProfile;
use Funnypot\Policy\Verdict as PolicyVerdict;
use Funnypot\Core\FakeHandle as CoreFakeHandle;
use Funnypot\Core\RequestContext as CoreRequestContext;
use Funnypot\Core\SiteProfile as CoreSiteProfile;
use Funnypot\Core\Verdict as CoreVerdict;

/**
 * Bridges core's two-phase engine (Funnypot\Core\Contracts\Evaluator: classify()+synthesize()) to the
 * policy's EvaluatorInterface, converting policy value objects to/from core's native types (design
 * §4.7). D authors NO decision logic here — it only translates.
 *
 * synthesize() takes the FakeHandle off the policy Verdict's opaque engineHandle, falling back to a
 * re-classify only for the policy's own invented verdicts (which never carried one). It used to
 * render needs (the policy Verdict does not carry one), then calls core synthesize(); core returning
 * null degrades to a plain 404 FakeResponse — the "only ever upgrade a 404" invariant. 7.3-clean
 * (no named args; core is PHP8 today and re-floors to 7.3 under C).
 */
final class CoreEvaluator implements EvaluatorInterface
{
    /** @var CoreEvaluatorContract */
    private $core;
    /** @var CoreRequestContext|null the current request, for synthesize() re-classification */
    private $ctx;

    public function __construct(CoreEvaluatorContract $core, $ctx = null)
    {
        $this->core = $core;
        $this->ctx = $ctx instanceof CoreRequestContext ? $ctx : null;
    }

    public function classify(RequestEvidence $request, PolicySiteProfile $profile)
    {
        $ctx = $this->ctx !== null ? $this->ctx : self::contextFromEvidence($request);
        $coreProfile = self::toCoreProfile($profile);
        $coreVerdict = $this->core->classify($ctx, $coreProfile);

        return self::toPolicyVerdict($coreVerdict, $profile, $request->path());
    }

    public function synthesize(PolicyVerdict $verdict, PolicySiteProfile $profile, string $seed)
    {
        $coreProfile = self::toCoreProfile($profile);

        // Fast path: the handle rode across on the Verdict itself, so there is nothing to recompute.
        $handle = self::decodeHandle($verdict->engineHandle());

        // Fallback, and it is NOT dead code. The policy invents its own Verdicts for the sacrificial
        // / pin / country-replay paths — those never came from classify(), so they carry no handle,
        // and this is the only way they can still be deceived rather than degrading to a plain 404.
        // It is also what keeps this adapter coherent: re-deriving PER PATH means a pinned actor
        // gets each path's own fake, where a single remembered handle would serve the wrong one.
        // Cost is not the reason it is second — classify() is ~4 us warm (a few O(1) hash probes,
        // not a scan of the template index); the handle is simply the more direct answer.
        if ($handle === null && $this->ctx !== null) {
            try {
                $reclassified = $this->core->classify($this->ctx, $coreProfile);
                $handle = $reclassified->fakeHandle;
            } catch (\Throwable $e) {
                $handle = null;
            }
        }

        $rendered = null;
        if ($handle !== null) {
            try {
                $rendered = $this->core->synthesizeFromHandle($handle, $coreProfile, $seed);
            } catch (\Throwable $e) {
                $rendered = null;
            }
        }

        if ($rendered === null) {
            return self::degrade(); // nothing to fake -> a plain 404 (never a 5xx)
        }

        return self::toPolicyFake($rendered);
    }

    // --- policy -> core --------------------------------------------------------------------------

    /** Build a core RequestContext from the neutral evidence (public so the adapter can pre-build it). */
    public static function contextFromEvidence(RequestEvidence $e)
    {
        $query = $e->query() !== array() ? http_build_query($e->query()) : '';
        $host = $e->header('host');

        return new CoreRequestContext(
            $e->method(),
            $e->path(),
            $query,
            $e->headers(),
            null,               // raw body is never carried (OAST hygiene); bot-signals need only headers
            $host !== null ? (string) $host : '',
            'https',
            ''
        );
    }

    private static function toCoreProfile(PolicySiteProfile $p)
    {
        $oracle = static function ($method, $path) use ($p) {
            return $p->routeExists($path) === true;
        };

        return new CoreSiteProfile(array($p->stack()), $oracle);
    }

    // --- core -> policy --------------------------------------------------------------------------

    /** Flatten core's opaque FakeHandle so the policy Verdict can carry it as bytes. */
    private static function encodeHandle($handle)
    {
        return $handle === null ? '' : (string) json_encode($handle->toArray());
    }

    /** Rebuild it on the far side. Anything malformed degrades to null, never an exception. */
    private static function decodeHandle($encoded)
    {
        if (!is_string($encoded) || $encoded === '') {
            return null;
        }
        $data = json_decode($encoded, true);

        return is_array($data) && isset($data['kind']) ? CoreFakeHandle::fromArray($data) : null;
    }

    private static function toPolicyVerdict(CoreVerdict $v, PolicySiteProfile $profile, $path)
    {
        $classification = $v->classification; // core + policy share the constant strings
        $matched = $v->detection->matched;
        $signal = $v->detection->clusterKey !== '' ? $v->detection->clusterKey : '';
        $severity = self::mapSeverity($v->severity);
        $onRealRoute = $profile->routeExists((string) $path);
        $bot = self::toPolicyBotSignals($v->signals);

        return new PolicyVerdict($classification, $matched, $signal, (int) $v->anomaly, $severity, $onRealRoute, $bot, self::encodeHandle($v->fakeHandle));
    }

    private static function toPolicyBotSignals($coreSet)
    {
        $flags = array();
        foreach ((array) $coreSet->flags as $name => $on) {
            if ($on === true) {
                $flags[] = (string) $name;
            }
        }

        return new PolicyBotSignals((string) $coreSet->uaClass, $flags, (string) $coreSet->fingerprint);
    }

    private static function mapSeverity($coreSeverity)
    {
        $s = strtolower((string) $coreSeverity);
        if ($s === 'high' || $s === 'critical') {
            return PolicyVerdict::SEVERITY_HIGH;
        }
        if ($s === 'medium') {
            return PolicyVerdict::SEVERITY_MEDIUM;
        }

        return PolicyVerdict::SEVERITY_LOW;
    }

    private static function toPolicyFake($rendered)
    {
        $headers = is_array($rendered->headers) ? $rendered->headers : array();
        $contentType = '';
        foreach ($headers as $k => $val) {
            if (strcasecmp((string) $k, 'Content-Type') === 0) {
                $contentType = (string) $val;
                break;
            }
        }

        return new PolicyFakeResponse((int) $rendered->status, $headers, (string) $rendered->body, $contentType);
    }

    /** The graceful "no fake" degrade: a plain 404 (upgrade-only invariant; never a 5xx). */
    private static function degrade()
    {
        return new PolicyFakeResponse(404, array(), '', 'text/html; charset=UTF-8');
    }
}
