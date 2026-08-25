<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Verdict;

/**
 * Replace the built-in report/block judgement wholesale.
 *
 * The default rules are deliberately conservative and turn on named flags rather than any
 * numeric threshold. Override this when you have host knowledge the sensor cannot have.
 *
 * funnypot-policy lands later as an implementation of this interface. check() keeps returning
 * an Assessment when it does — that is the point of a sensor-owned type at the boundary.
 */
interface Judge
{
    /**
     * @return array{report:bool,block:bool,reason:string}
     */
    public function judge(Verdict $verdict, RequestContext $request, string $profile): array;
}
