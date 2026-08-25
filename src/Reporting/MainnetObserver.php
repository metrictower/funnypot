<?php

declare(strict_types=1);

namespace Funnypot\Sensor\Reporting;

use Funnypot\Sensor\Funnypot;
use Funnypot\Core\Detection;
use Funnypot\Core\Observer;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;

/**
 * Core's app-policy seam, wired to mainnet reporting.
 *
 * Core calls an Observer only on the respond() path — including onDetection — so this is the
 * hook for a deception deployment that serves fakes. A detect-only embedder gains nothing from
 * an Observer and should call Funnypot::check()/report() at its own call site instead.
 *
 * Reporting here is enqueue-only and never vetoes: onDetection queues, shouldRespond always
 * agrees, onOutcome is a no-op. A mainnet problem must never change what the visitor is served.
 */
final class MainnetObserver implements Observer
{
    /** @var Funnypot */
    private $funnypot;

    /** @var callable():string resolves the client IP, which core never sees */
    private $ipResolver;

    /**
     * @param callable():string $ipResolver returns the client IP for the request in flight
     */
    public function __construct(Funnypot $funnypot, callable $ipResolver)
    {
        $this->funnypot = $funnypot;
        $this->ipResolver = $ipResolver;
    }

    /**
     * Re-checks rather than reporting on the Detection core hands over.
     *
     * A Detection carries no classification, so reporting on it means reporting on a bare corpus
     * match — the mistake this package exists to prevent. check() costs a few microseconds (the
     * route lookup is a handful of O(1) hash probes) and gives this path the identical judgement
     * an embedder gets at their own call site. One dialect, not two.
     *
     * Core drops the Verdict at this seam; widening Observer to carry it removes the re-check.
     */
    public function onDetection(RequestContext $r, Detection $detection): void
    {
        $resolve = $this->ipResolver;
        $ip = (string) $resolve();
        if ($ip === '') {
            return;
        }

        $this->funnypot->report($ip, $this->funnypot->check($r));
    }

    /**
     * Never veto on reporting grounds — what gets served is a deception decision, not an
     * intel one.
     */
    public function shouldRespond(RequestContext $r, Detection $detection): bool
    {
        return true;
    }

    public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
    {
        // Nothing to record here yet; onDetection already queued the report.
    }
}
