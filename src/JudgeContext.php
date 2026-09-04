<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\SiteProfile;

/**
 * What the sensor knows about a request that is on neither the Verdict nor the RequestContext.
 *
 * Core's RequestContext is IP-blind by design, and the route oracle lives on the SiteProfile the
 * Detector owns — a policy implementation needs both. A sensor-owned value type at the boundary
 * means the next thing a Judge needs is an added accessor here, not another signature break.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, no promotion/match/enums.
 */
final class JudgeContext
{
    /** @var string one of Funnypot's PROFILE_* constants */
    private $posture;

    /** @var string the client address as the host supplied it; '' when it supplied none */
    private $ip;

    /** @var SiteProfile carries the host's own_routes oracle as hasRoute($method, $path) */
    private $profile;

    public function __construct(string $posture, string $ip, SiteProfile $profile)
    {
        $this->posture = $posture;
        $this->ip = $ip;
        $this->profile = $profile;
    }

    /** Funnypot::PROFILE_APP or Funnypot::PROFILE_HONEYPOT. */
    public function posture(): string
    {
        return $this->posture;
    }

    /**
     * The client address. Never '' inside Judge::judge() — check() fails open before it would
     * call a Judge with no IP — but '' when built by hand without one.
     */
    public function ip(): string
    {
        return $this->ip;
    }

    /** Core's SiteProfile: the host's real-route oracle, so a Judge can ask hasRoute() itself. */
    public function profile(): SiteProfile
    {
        return $this->profile;
    }
}
