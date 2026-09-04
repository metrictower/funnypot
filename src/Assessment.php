<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\Verdict;
use LogicException;

/**
 * What funnypot concluded about one request, and what you should do about it.
 *
 * Three verbs — report, block, deceive — and they are the only decisions in the class. Everything
 * else is evidence: always populated, never gated, there for your log row.
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

    /** @var object|null what to serve instead of the real response; null unless a Judge chose deceive */
    private $fake;

    /**
     * @param object|null $fake
     */
    public function __construct(
        Verdict $verdict,
        string $kind,
        bool $report,
        bool $block,
        string $reason,
        $fake = null
    ) {
        $this->verdict = $verdict;
        $this->kind = $kind;
        $this->report = $report;
        $this->block = $block;
        $this->reason = $reason;
        $this->fake = $fake;
    }

    /** Send this IP to mainnet. */
    public function shouldReport(): bool
    {
        return $this->report;
    }

    /** Refuse this request. Never true alongside shouldDeceive(): a block is a tell. */
    public function shouldBlock(): bool
    {
        return $this->block;
    }

    /**
     * Serve fake() in place of the real response.
     *
     * Only a Judge raises this. The default rules never deceive — under PROFILE_HONEYPOT they
     * report and leave the decoy to the host — so without a Judge this is always false.
     */
    public function shouldDeceive(): bool
    {
        return $this->fake !== null;
    }

    /**
     * The response to serve when shouldDeceive(). Whatever object the Judge handed over —
     * funnypot-policy's FakeResponse in practice; the sensor never reads it.
     *
     * @return object|null
     */
    public function fake()
    {
        return $this->fake;
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
     * How strong this evidence is, as a graded increment rather than a bit.
     *
     * Hosts accumulate this against an actor and act on the total. Collapsing detection to one
     * boolean is what turns a single false positive into an immediate ban — every hand-rolled
     * scorer in the estate is graded for exactly that reason.
     *
     * The scale is funnypot-policy's, documented on `StateStoreInterface::decayScore`:
     * **+1 soft / +10 medium / +100 hard-tell**. Using the same numbers means a host can feed
     * this straight into policy's store without a translation table.
     *
     * Derived from kind(), NOT from a Judge — policy's `Decision` exposes no score of its own
     * (it writes increments to its store internally and returns action/reason only). Deriving it
     * here means the number means the same thing whether or not a Judge is configured, which is
     * the property a host accumulating it actually needs.
     *
     * Distinct from anomaly(): that is request SHAPE (how odd the client looks), this is evidence
     * STRENGTH (how sure we are the request is a probe). They are not interchangeable.
     */
    public function score(): int
    {
        if ($this->kind === Verdict::ATTACK_CLASS) {
            return 100;
        }
        if ($this->kind === Verdict::SCANNER_PROBE) {
            return 10;
        }
        if ($this->kind === self::AMBIENT) {
            // A path every site is asked for. Soft on its own; a named scanner UA on the same
            // request is what makes it worth acting on.
            //
            // Reads the signal flag, NOT reason(): a Judge overwrites reason with its own closed
            // label set, and funnypot-policy's does not contain 'scanner-ua' — so keying on the
            // string silently scored this 1 instead of 10 whenever a Judge was configured, which
            // is exactly the judge-dependence the docblock above promises there is none of.
            return $this->verdict->signals->has(BotSignalSet::SCANNER_USER_AGENT) ? 10 : 1;
        }

        return 0;
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
     * Why the verbs came out the way they did. Closed set under the default rules:
     * clean | ambient | robots-exempt | scanner-ua | scripting-ua | probe | attack | honeypot-profile
     *
     * With a Judge configured it is the Judge's own label ('judge' when it gives none), or
     * 'no-client-ip' when check() was called without the IP the Judge needs and failed open.
     * The label stays the Judge's even where the sensor cleared a verb the ruling had set
     * (Detector::clamp()); the verbs say what happens, the reason says who decided.
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
            'score' => $this->score(),
            'report' => $this->report,
            'block' => $this->block,
            'deceive' => $this->shouldDeceive(),
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
                . 'Use shouldReport(), shouldBlock() or shouldDeceive().'
            );
        }

        throw new LogicException('Funnypot: unknown Assessment property $' . $name . '.');
    }
}
