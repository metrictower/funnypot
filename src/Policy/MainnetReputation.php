<?php

declare(strict_types=1);

namespace Funnypot\Sensor\Policy;

use Funnypot\Mainnet\CheckResult;
use Funnypot\Mainnet\Client;
use Funnypot\Policy\Port\ReputationInterface;
use Funnypot\Policy\ReputationVerdict;

/**
 * The actor-evidence port over piece F. CACHE-FIRST, request-path-safe (M5): `lookup()` consults F's
 * already-resolved per-IP verdict via Client::cachedVerdict() — it NEVER opens a socket and never
 * touches the breaker. A fresh Client::check() runs only out-of-band (the warmer / mirror-sync) and
 * populates the cache this port reads.
 *
 * The O1 local blacklist mirror is consulted FIRST by the policy engine itself (StateStore::mirrorVerdict),
 * so this port is the escalation read. Inert (always fail-open `unknown`) unless the operator enabled
 * checking AND set a key (F's checkActive() enforces the same gate).
 */
final class MainnetReputation implements ReputationInterface
{
    /** @var Client */
    private $client;

    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    public function lookup(string $ip): ReputationVerdict
    {
        try {
            $result = $this->client->cachedVerdict($ip);
        } catch (\Throwable $ignored) {
            return ReputationVerdict::failOpen();
        }

        if (!$result instanceof CheckResult) {
            return ReputationVerdict::failOpen();
        }

        $context = $result->context();
        $usageType = isset($context['usage_type']) ? (string) $context['usage_type'] : null;

        return new ReputationVerdict(
            $result->verdict(),
            $result->score(),
            $this->source($result->source()),
            $usageType
        );
    }

    private function source(string $fSource): string
    {
        if ($fSource === CheckResult::SOURCE_CACHE || $fSource === CheckResult::SOURCE_FRESH) {
            return ReputationVerdict::SOURCE_CACHE;
        }

        return ReputationVerdict::SOURCE_FAIL_OPEN;
    }
}
