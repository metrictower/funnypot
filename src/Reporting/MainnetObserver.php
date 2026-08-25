<?php

declare(strict_types=1);

namespace Funnypot\Bundle\Reporting;

use Funnypot\Bundle\Funnypot;
use Funnypot\Detection;
use Funnypot\Observer;
use Funnypot\RequestContext;
use Funnypot\SynthesizedResponse;

/**
 * Core's app-policy seam, wired to mainnet reporting.
 *
 * Core calls an Observer only on the respond() path — including onDetection — so this is the
 * hook for a deception deployment that serves fakes. A detect-only embedder gains nothing from
 * an Observer and should call Funnypot::inspect()/report() at its own call site instead.
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

    public function onDetection(RequestContext $r, Detection $detection): void
    {
        $resolve = $this->ipResolver;
        $ip = (string) $resolve();
        if ($ip === '') {
            return;
        }

        $this->funnypot->report($ip, $detection);
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
