<?php

declare(strict_types=1);

namespace Funnypot\Sensor\Tests;

use ArrayIterator;
use Funnypot\Core\RequestContext;
use Funnypot\Sensor\Detector;
use Funnypot\Sensor\Funnypot;
use Funnypot\Sensor\RouteOracle;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * RouteOracle::bareSegments() is the own_routes oracle for the 404-handler mount. It owns the
 * root and the exact bare first segment of every literal route — the group prefixes that 404
 * and still score as probes — and nothing deeper, so the corpus keeps seeing /admin/config.php.
 */
final class RouteOracleTest extends TestCase
{
    /** A Laravel host's route table as the RUNTIME router lists it: group prefixes folded in. */
    private const ROUTES = array(
        '/',
        'login',
        'logout',
        'security/audit',
        'security/keys/{id}',
        'api/v1/users',
        'api/v1/users/{id}',
        'admin/dashboard',
        '{sourceMapPath}',
    );

    private const CHROME = array(
        'Host' => 'app.example.com',
        'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language' => 'en-GB,en;q=0.9',
        'Accept-Encoding' => 'gzip, deflate, br',
        'Sec-Fetch-Mode' => 'navigate',
    );

    private function request(string $path): RequestContext
    {
        return new RequestContext('GET', $path, '', self::CHROME, null, 'app.example.com');
    }

    public function test_a_bare_route_group_prefix_is_owned_and_a_deeper_path_is_not(): void
    {
        $owns = RouteOracle::bareSegments(self::ROUTES);

        foreach (array('/security', '/api', '/admin', '/login', '/logout') as $prefix) {
            self::assertTrue($owns('GET', $prefix), $prefix . ' is the bare prefix of a route group');
        }

        // Deeper than the prefix is nothing the app publishes — the corpus must still see it.
        foreach (array('/security/nope', '/admin/config.php', '/api/v1/debug') as $deep) {
            self::assertFalse($owns('GET', $deep), $deep . ' must still be inspected');
        }

        // An exact registered route is not owned either: it resolves, so it never 404s.
        self::assertFalse($owns('GET', '/security/audit'));
    }

    public function test_the_front_door_is_owned(): void
    {
        $owns = RouteOracle::bareSegments(array('login'));

        self::assertTrue($owns('GET', '/'));
        self::assertTrue($owns('GET', ''));
        self::assertTrue($owns('GET', '/?utm_source=newsletter'));
    }

    public function test_a_trailing_slash_a_capital_or_a_query_is_not_a_different_path(): void
    {
        $owns = RouteOracle::bareSegments(self::ROUTES);

        self::assertTrue($owns('GET', '/security/'));
        self::assertTrue($owns('GET', '/Security'));
        self::assertTrue($owns('GET', '/SECURITY/'));
        self::assertTrue($owns('GET', '/security?redirect=%2Fsecurity%2Fkeys'));
        self::assertTrue($owns('GET', '/security#top'));
    }

    public function test_a_parameter_first_route_owns_nothing(): void
    {
        foreach (array('{sourceMapPath}', '{any?}', ':controller/:action') as $catchAll) {
            $owns = RouteOracle::bareSegments(array($catchAll));

            self::assertTrue($owns('GET', '/'));
            self::assertFalse($owns('GET', '/anything'), $catchAll . ' must not own every path');
            self::assertFalse($owns('GET', '/wp-login.php'), $catchAll . ' must not own every path');
            self::assertFalse($owns('GET', '/' . $catchAll), 'a placeholder must not own its literal text');
        }
    }

    public function test_an_unknown_segment_is_still_inspected(): void
    {
        $owns = RouteOracle::bareSegments(self::ROUTES);

        foreach (array('/wp-login.php', '/.env', '/phpmyadmin', '/securityx', '/log') as $probe) {
            self::assertFalse($owns('GET', $probe), $probe);
        }
    }

    public function test_the_method_does_not_matter(): void
    {
        $owns = RouteOracle::bareSegments(self::ROUTES);

        foreach (array('GET', 'POST', 'DELETE', 'OPTIONS', 'get') as $method) {
            self::assertTrue($owns($method, '/security'), $method);
            self::assertFalse($owns($method, '/security/nope'), $method);
        }
    }

    /**
     * A framework's router is empty while its config is still being read, so a callable must
     * not be enumerated at build time — and, the router being stable within a process, once
     * enumerated it must not be enumerated again.
     */
    public function test_a_callable_is_enumerated_lazily_and_once(): void
    {
        $calls = 0;
        $owns = RouteOracle::bareSegments(static function () use (&$calls) {
            $calls++;

            return self::ROUTES;
        });
        self::assertSame(0, $calls, 'building the oracle must not touch the router');

        self::assertTrue($owns('GET', '/security'));
        self::assertFalse($owns('GET', '/wp-login.php'));
        self::assertTrue($owns('GET', '/api'));
        self::assertSame(1, $calls, 'the route table is read once per oracle');
    }

    public function test_two_oracles_do_not_share_a_route_table(): void
    {
        $ownsSecurity = RouteOracle::bareSegments(static function () {
            return array('security/audit');
        });
        $ownsApi = RouteOracle::bareSegments(static function () {
            return array('api/v1/users');
        });

        self::assertTrue($ownsSecurity('GET', '/security'));
        self::assertTrue($ownsApi('GET', '/api'));
        self::assertFalse($ownsSecurity('GET', '/api'), 'one oracle must not see another\'s routes');
        self::assertFalse($ownsApi('GET', '/security'), 'one oracle must not see another\'s routes');
    }

    /**
     * The one wiring mistake a lazy provider invites: the first check arrives before the routes
     * are registered. An empty table is answered for that request and forgotten, never cached,
     * so the boot-time router cannot decide every later request.
     */
    public function test_an_empty_router_is_not_remembered(): void
    {
        $calls = 0;
        $owns = RouteOracle::bareSegments(static function () use (&$calls) {
            $calls++;

            return $calls === 1 ? array() : array('security/audit');
        });

        self::assertFalse($owns('GET', '/security'), 'nothing is owned while the router is empty');
        self::assertTrue($owns('GET', '/security'), 'the populated router is seen on the next check');
        self::assertTrue($owns('GET', '/security'));
        self::assertSame(2, $calls, 'the populated table is cached; only the empty one was retried');
    }

    public function test_it_accepts_a_traversable_and_a_generator(): void
    {
        $fromIterator = RouteOracle::bareSegments(new ArrayIterator(self::ROUTES));
        $fromGenerator = RouteOracle::bareSegments(static function () {
            foreach (self::ROUTES as $uri) {
                yield $uri;
            }
        });

        foreach (array($fromIterator, $fromGenerator) as $owns) {
            self::assertTrue($owns('GET', '/security'));
            self::assertFalse($owns('GET', '/security/nope'));
            self::assertFalse($owns('GET', '/wp-login.php'));
        }
    }

    public function test_it_rejects_anything_that_is_not_a_route_list(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/route URI patterns as an array, a Traversable, or a callable/');

        RouteOracle::bareSegments(42);
    }

    public function test_it_rejects_route_objects_in_place_of_their_uris(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/map your router.s route objects to their URI/');

        RouteOracle::bareSegments(array('login', new stdClass()));
    }

    public function test_a_provider_that_returns_no_list_is_rejected_on_first_use(): void
    {
        $owns = RouteOracle::bareSegments(static function () {
            return 'security';
        });

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/expected a list of route URI patterns, got string/');

        $owns('GET', '/security');
    }

    /**
     * The bug this helper exists for, end to end: under ONLY_ON_404 a real browser on a bare
     * route-group prefix is reported AND blocked. With the oracle it is neither — while a probe
     * deeper under an owned prefix, and one off an unknown segment, are still both.
     */
    public function test_a_browser_on_a_bare_prefix_is_no_longer_reported_end_to_end(): void
    {
        $shortcut = Detector::fromArray(array('own_routes' => Funnypot::ONLY_ON_404));
        $oracle = Detector::fromArray(array('own_routes' => RouteOracle::bareSegments(self::ROUTES)));

        foreach (array('/security', '/security/', '/Security', '/api', '/admin', '/login', '/logout') as $prefix) {
            $trap = $shortcut->check($this->request($prefix));
            self::assertTrue($trap->shouldReport(), $prefix . ' is the trap: reported under ONLY_ON_404');
            self::assertTrue($trap->shouldBlock(), $prefix . ' is the trap: blocked under ONLY_ON_404');

            $check = $oracle->check($this->request($prefix));
            self::assertFalse($check->shouldReport(), $prefix . ' is a route-group prefix of the host');
            self::assertFalse($check->shouldBlock(), $prefix . ' is a route-group prefix of the host');
            self::assertSame('clean', $check->kind());
        }

        foreach (array('/admin/config.php', '/wp-login.php') as $probe) {
            $check = $oracle->check($this->request($probe));
            self::assertTrue($check->shouldReport(), $probe . ' must still be reported');
            self::assertTrue($check->shouldBlock(), $probe . ' must still be blocked');
        }
    }

    /** The shortcut must stop reading as the recommended path: both oracle errors name the helper. */
    public function test_the_own_routes_errors_point_at_the_helper(): void
    {
        foreach (array(array(), array('own_routes' => 'nope')) as $config) {
            try {
                Detector::fromArray($config);
                self::fail('a missing or non-callable own_routes must be refused');
            } catch (InvalidArgumentException $e) {
                self::assertStringContainsString('RouteOracle::bareSegments(', $e->getMessage());
            }
        }
    }
}
