<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\Verdict;
use LogicException;

/**
 * What funnypot concluded about one request, and what you should do about it.
 *
 * Two verbs, and they are the only booleans in the class. Everything else is evidence: always
 * populated, never gated, there for your log row.
 *
 * The shape is deliberate. A corpus match is not a decision — `/favicon.ico` matches 24 nuclei
 * templates and `/` matches 1,590, because the corpus carries technology-fingerprint templates
 * next to exploit ones and scanners probe the paths real apps have. Anything that reads like
 * state ("matched", "actionable") invites being used as the gate, so this class has no boolean
 * properties at all and __get() refuses the two most tempting names by hand.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, no promotion/match/enums.
 */
final class Assessment
{
    /**
     * Paths every site gets asked for whether or not it has them. Same strings as core's
     * classification vocabulary, so this moves to Verdict::AMBIENT unchanged.
     */
    public const AMBIENT = 'ambient';

    /** @var Verdict */
    private $verdict;

    /** @var string one of Verdict's classification constants, or self::AMBIENT */
    private $kind;

    /** @var bool */
    private $report;

    /** @var bool */
    private $block;

    /** @var string closed label set — see reason() */
    private $reason;

    public function __construct(
        Verdict $verdict,
        string $kind,
        bool $report,
        bool $block,
        string $reason
    ) {
        $this->verdict = $verdict;
        $this->kind = $kind;
        $this->report = $report;
        $this->block = $block;
        $this->reason = $reason;
    }

    /** Send this IP to mainnet. */
    public function shouldReport(): bool
    {
        return $this->report;
    }

    /** Refuse this request. */
    public function shouldBlock(): bool
    {
        return $this->block;
    }

    /**
     * What the request IS, in core's own vocabulary — no second dialect.
     *
     * clean | ambient | scanner-probe | attack-class | suspicious
     */
    public function kind(): string
    {
        return $this->kind;
    }

    /** Highest nuclei severity across the match, '' when nothing matched. Evidence, never a gate. */
    public function severity(): string
    {
        return $this->verdict->severity;
    }

    /**
     * Cumulative request-shape anomaly. Evidence for the log row, NEVER a gate.
     *
     * Measured: it is path-blind — the same client scores the same on /robots.txt and on /.env —
     * and the bands interleave, with UptimeRobot at 24 and Googlebot at 19 both above curl at 14.
     * There is no threshold to pick. That is why the judgement below turns on named flags.
     */
    public function anomaly(): int
    {
        return $this->verdict->anomaly;
    }

    public function signals(): BotSignalSet
    {
        return $this->verdict->signals;
    }

    /** @return string[] */
    public function templateIds(): array
    {
        return $this->verdict->detection->templateIds();
    }

    /** @return string[] */
    public function tags(): array
    {
        return $this->verdict->detection->tags();
    }

    /**
     * Why the two verbs came out the way they did. Closed set:
     * clean | ambient | own-route | scanner-ua | probe | attack | honeypot-profile | judge
     */
    public function reason(): string
    {
        return $this->reason;
    }

    /** The full core verdict. A deliberate escape hatch: you have to name what you want. */
    public function verdict(): Verdict
    {
        return $this->verdict;
    }

    /**
     * One log row, ready to store.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return array(
            'kind' => $this->kind,
            'report' => $this->report,
            'block' => $this->block,
            'reason' => $this->reason,
            'severity' => $this->verdict->severity,
            'anomaly' => $this->verdict->anomaly,
            'signals' => $this->verdict->signals->toArray(),
            'template_ids' => $this->verdict->detection->templateIds(),
            'tags' => $this->verdict->detection->tags(),
        );
    }

    /**
     * There are no public properties. This exists to catch the one mistake this class was
     * shaped to prevent, and it fires in coercive mode too.
     *
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        if ($name === 'matched' || $name === 'actionable') {
            throw new LogicException(
                'Funnypot: Assessment has no $' . $name . '. A corpus match is not a decision — '
                . '/favicon.ico matches 24 templates and / matches 1590. '
                . 'Use shouldReport() or shouldBlock().'
            );
        }

        throw new LogicException('Funnypot: unknown Assessment property $' . $name . '.');
    }
}
