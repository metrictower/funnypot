<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Verdict;

/**
 * Replace the built-in report/block judgement.
 *
 * The default rules are deliberately conservative and turn on named flags rather than any
 * numeric threshold. Override this when you have host knowledge the sensor cannot have.
 *
 * funnypot-policy plugs in as an implementation of this interface. check() keeps returning an
 * Assessment when it does — that is the point of a sensor-owned type at the boundary.
 *
 * A ruling is not the last word on everything. The sensor keeps a short list of guarantees
 * whatever a Judge says — an ambient path is never blocked and never reported for a plain
 * browser, PROFILE_HONEYPOT never blocks, a deceiving ruling never blocks, a clean request is
 * never reported. Each is a ceiling: it can clear a verb the ruling set, never set one the
 * ruling cleared. The list lives in one place, Detector::clamp(); an implementation need not
 * re-derive it and cannot turn it off.
 *
 * A Judge may keep state: funnypot-policy's reads and writes its store on every ruling. That is
 * why check() consults it only when the host supplied a client IP, and why Detector::checkPure()
 * exists for call sites that must not advance an actor's state a second time.
 */
interface Judge
{
    /**
     * Rule on one request.
     *
     * 'fake' is the deceive channel: an object (funnypot-policy's FakeResponse, or your own) the
     * host should serve in place of its real response. A ruling that carries one never blocks —
     * blocking is a tell, and deceive exists to avoid it — so check() clears 'block' whenever
     * 'fake' is set. Anything that is not an object counts as no fake.
     *
     * 'reason' is a short label for the log row. Keep it to a closed set of your own: never a
     * payload, never a signature string.
     *
     * @return array{report:bool,block:bool,reason:string,fake?:object|null}
     */
    public function judge(Verdict $verdict, RequestContext $request, JudgeContext $context): array;
}
