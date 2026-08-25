<?php

declare(strict_types=1);

namespace Funnypot\Sensor\Tests;

use Funnypot\Core\Detection;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Verdict;
use Funnypot\Sensor\Assessment;
use Funnypot\Sensor\Funnypot;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;
use TypeError;

final class FunnypotTest extends TestCase
{
    /** Full-header desktop Chrome — the client that must never be reported on a real route. */
    private const CHROME = array(
        'Host' => 'app.example.com',
        'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language' => 'en-GB,en;q=0.9',
        'Accept-Encoding' => 'gzip, deflate, br',
        'Sec-Fetch-Mode' => 'navigate',
        'Sec-Fetch-Site' => 'none',
        'Sec-CH-UA' => '"Chromium";v="120"',
        'Sec-CH-UA-Platform' => '"macOS"',
    );

    /** @return array<string,mixed> */
    private function config(array $overrides = array()): array
    {
        return array_merge(array(
            'base_url' => 'https://mainnet.example',
            'key' => 'test-key',
            'self_ips' => array('203.0.113.7'),
            'intel_db_path' => ':memory:',
            'own_routes' => Funnypot::ONLY_ON_404,
        ), $overrides);
    }

    /** @param array<string,string> $headers */
    private function request(string $path, array $headers = self::CHROME, string $host = 'app.example.com'): RequestContext
    {
        return new RequestContext('GET', $path, '', $headers, null, $host);
    }

    public function test_it_refuses_to_start_without_a_key(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"key" is required/');

        Funnypot::fromArray($this->config(array('key' => '')));
    }

    public function test_it_refuses_to_start_without_self_ips(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"self_ips" is required/');

        Funnypot::fromArray($this->config(array('self_ips' => array())));
    }

    public function test_it_refuses_to_start_without_a_queue_path(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"intel_db_path" is required/');

        Funnypot::fromArray($this->config(array('intel_db_path' => '')));
    }

    public function test_an_app_refuses_to_start_without_a_route_oracle(): void
    {
        $config = $this->config();
        unset($config['own_routes']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"own_routes" is required/');

        Funnypot::fromArray($config);
    }

    public function test_a_honeypot_needs_no_route_oracle(): void
    {
        $config = $this->config(array('profile' => Funnypot::PROFILE_HONEYPOT));
        unset($config['own_routes']);

        self::assertInstanceOf(Funnypot::class, Funnypot::fromArray($config));
    }

    public function test_the_old_severity_knob_is_a_loud_error_not_a_silent_no_op(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"min_severity" no longer exists/');

        Funnypot::fromArray($this->config(array('min_severity' => 'high')));
    }

    /**
     * The bug this redesign exists for. At the old default floor of 'high', a real browser was
     * reportable on 8 of these; / and /index.php and /login are all critical in the corpus.
     */
    public function test_a_real_browser_on_a_declared_route_is_never_reported(): void
    {
        $own = array('/', '/login', '/admin', '/dashboard', '/register', '/search', '/api/v1/users', '/index.php');
        $funnypot = Funnypot::fromArray($this->config(array(
            'own_routes' => static function ($method, $path) use ($own) {
                return in_array($path, $own, true);
            },
        )));

        foreach ($own as $path) {
            $check = $funnypot->check($this->request($path));
            self::assertFalse($check->shouldReport(), $path . ' is a declared real route');
            self::assertFalse($check->shouldBlock(), $path . ' is a declared real route');
        }
    }

    public function test_a_genuine_probe_is_still_reported(): void
    {
        $funnypot = Funnypot::fromArray($this->config());

        foreach (array('/wp-login.php', '/.env', '/.git/config', '/phpmyadmin/index.php') as $path) {
            $check = $funnypot->check($this->request($path));
            self::assertTrue($check->shouldReport(), $path);
            self::assertTrue($check->shouldBlock(), $path . ' has no business being requested here');
        }
    }

    public function test_ambient_paths_are_not_reported_for_a_browser(): void
    {
        $funnypot = Funnypot::fromArray($this->config());

        foreach (array('/favicon.ico', '/robots.txt', '/sitemap.xml', '/manifest.json', '/browserconfig.xml', '/.well-known/security.txt') as $path) {
            $check = $funnypot->check($this->request($path));
            self::assertFalse($check->shouldReport(), $path . ' is ambient — every site is asked for it');
        }
    }

    public function test_an_ambient_path_from_a_scanner_ua_is_reported(): void
    {
        $funnypot = Funnypot::fromArray($this->config());

        $check = $funnypot->check($this->request('/robots.txt', array(
            'Host' => 'app.example.com',
            'User-Agent' => 'Mozilla/5.0 zgrab/0.x',
        )));

        self::assertTrue($check->shouldReport(), 'a named scanner UA is the flag, not the anomaly score');
        self::assertSame('scanner-ua', $check->reason());

        // Refusing a /robots.txt fetch gains nothing and costs a crawler when the UA match is wrong.
        self::assertFalse($check->shouldBlock(), 'ambient paths are never blocked');
    }

    /** Never a prefix rule: the corpus carries these as genuine probes. */
    public function test_ambient_matching_is_exact_and_root_anchored(): void
    {
        $funnypot = Funnypot::fromArray($this->config());

        foreach (array('/actuator/favicon.ico', '/web/manifest.json') as $path) {
            self::assertNotSame(Assessment::AMBIENT, $funnypot->check($this->request($path))->kind(), $path);
        }
    }

    public function test_a_honeypot_reports_ambient_chatter_and_never_blocks(): void
    {
        $funnypot = Funnypot::fromArray($this->config(array('profile' => Funnypot::PROFILE_HONEYPOT)));

        $ambient = $funnypot->check($this->request('/favicon.ico'));
        self::assertTrue($ambient->shouldReport(), 'nothing legitimate reaches a honeypot');
        self::assertSame(Assessment::AMBIENT, $ambient->kind(), 'the kind is unchanged by the profile');

        // Blocking would tell the attacker they were detected.
        self::assertFalse($funnypot->check($this->request('/.env'))->shouldBlock());
    }

    /**
     * /robots.txt is the one ambient path exempt from PROFILE_HONEYPOT's otherwise-unconditional
     * reporting. A well-behaved crawler is expected to fetch it even on a box with nothing real
     * behind it, and reporting compliant behaviour earns nothing.
     */
    public function test_robots_txt_is_exempt_from_honeypot_reporting(): void
    {
        $funnypot = Funnypot::fromArray($this->config(array('profile' => Funnypot::PROFILE_HONEYPOT)));

        $check = $funnypot->check($this->request('/robots.txt'));

        self::assertFalse($check->shouldReport());
        self::assertSame(Assessment::AMBIENT, $check->kind(), 'evidence is unaffected by the exemption');
        self::assertSame('robots-exempt', $check->reason());

        // The exemption is scoped to /robots.txt only, and to PROFILE_HONEYPOT only.
        self::assertTrue(
            $funnypot->check($this->request('/favicon.ico'))->shouldReport(),
            'other ambient paths are unaffected'
        );

        $app = Funnypot::fromArray($this->config());
        self::assertFalse(
            $app->check($this->request('/robots.txt'))->shouldReport(),
            'PROFILE_APP already never reports robots.txt from a plain browser — nothing to exempt'
        );
    }

    public function test_the_profile_moves_the_verbs_and_nothing_else(): void
    {
        $app = Funnypot::fromArray($this->config());
        $pot = Funnypot::fromArray($this->config(array('profile' => Funnypot::PROFILE_HONEYPOT)));

        $a = $app->check($this->request('/robots.txt'))->toArray();
        $b = $pot->check($this->request('/robots.txt'))->toArray();

        unset($a['report'], $a['block'], $a['reason'], $b['report'], $b['block'], $b['reason']);
        self::assertSame($a, $b, 'evidence is never gated by profile — funnypot-app logs the same row');
    }

    public function test_ambient_list_is_tunable(): void
    {
        $funnypot = Funnypot::fromArray($this->config(array(
            'ambient_extra' => array('/healthz'),
            'ambient_drop' => array('/manifest.json'),
        )));

        self::assertSame(Assessment::AMBIENT, $funnypot->check($this->request('/healthz'))->kind());
        self::assertNotSame(Assessment::AMBIENT, $funnypot->check($this->request('/manifest.json'))->kind());
    }

    public function test_report_refuses_an_assessment_that_says_not_to(): void
    {
        $funnypot = Funnypot::fromArray($this->config());
        $check = $funnypot->check($this->request('/favicon.ico'));

        $result = $funnypot->report('198.51.100.9', $check);

        self::assertFalse($result['queued']);
        self::assertSame('ambient', $result['reason']);
    }

    // ── the misuse the shape exists to prevent ──

    public function test_reading_matched_off_an_assessment_throws_a_teaching_error(): void
    {
        $check = Funnypot::fromArray($this->config())->check($this->request('/'));

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/Use shouldReport\(\) or shouldBlock\(\)/');

        /** @noinspection PhpUndefinedFieldInspection */
        $check->matched;
    }

    public function test_reading_actionable_off_an_assessment_throws_too(): void
    {
        $check = Funnypot::fromArray($this->config())->check($this->request('/'));

        $this->expectException(LogicException::class);

        /** @noinspection PhpUndefinedFieldInspection */
        $check->actionable;
    }

    /** Going around the facade to core and passing the raw Detection cannot be made to work. */
    public function test_report_will_not_accept_a_core_detection(): void
    {
        $funnypot = Funnypot::fromArray($this->config());

        $this->expectException(TypeError::class);

        /** @phpstan-ignore-next-line — this is the assertion */
        $funnypot->report('198.51.100.9', Detection::none());
    }

    public function test_the_deleted_surface_is_gone(): void
    {
        self::assertFalse(method_exists(Funnypot::class, 'inspect'));
        self::assertFalse(method_exists(Funnypot::class, 'reportable'));
        self::assertFalse(defined(Funnypot::class . '::DEFAULT_MIN_SEVERITY'));
    }

    public function test_evidence_survives_a_clean_verdict(): void
    {
        $check = Funnypot::fromArray($this->config())->check($this->request('/robots.txt'));

        self::assertSame(Assessment::AMBIENT, $check->kind());
        self::assertNotSame(array(), $check->templateIds(), 'the raw match is still there for the log');
        self::assertIsInt($check->anomaly());
    }

    public function test_a_custom_judge_overrides_the_default_rules(): void
    {
        $funnypot = Funnypot::fromArray($this->config(array(
            'judge' => new class implements \Funnypot\Sensor\Judge {
                public function judge(Verdict $verdict, RequestContext $request, string $profile): array
                {
                    return array('report' => false, 'block' => true, 'reason' => 'mine');
                }
            },
        )));

        $check = $funnypot->check($this->request('/.env'));

        self::assertFalse($check->shouldReport());
        self::assertTrue($check->shouldBlock());
        self::assertSame('mine', $check->reason());
    }
}
