<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

use InvalidArgumentException;
use Traversable;

/**
 * The own_routes oracle for the 404-handler mount, built from the routes a router can list.
 *
 * Funnypot::ONLY_ON_404 says "nothing reaching a 404 handler is a real route", and a framework
 * app breaks that in one specific way: a route group's bare prefix has no route of its own.
 * A group with prefix 'security' registers security/foo and security/bar, never security, so
 * a stale bookmark to /security 404s, reaches the sensor, and is matched against a corpus that
 * carries /security, /api, /admin and /login precisely because real apps have them. Measured on
 * a Laravel host that followed the ONLY_ON_404 advice: all seven of its group prefixes
 * classified scanner-probe — report and block — and one banned a colleague.
 *
 * The rule is EXACT BARE SEGMENT, never subtree. Over the 5,196-key corpus against that host's
 * 83 runtime segments, owning the whole subtree under each prefix forfeits 441 detections
 * (8.51% — /api 294, /admin 58, /login 26) and hands a scanner /admin/config.php; owning only
 * the bare segment forfeits 20 (0.39%), every one a route group of the host. Do not widen it.
 *
 *  - '/' is owned: the app's own front door is not a probe.
 *  - '/security', '/security/' and '/Security' are owned when some route's first segment is
 *    'security'. A trailing slash or a capital is not a different path to a human.
 *  - '/security/nope' and '/admin/config.php' are NOT owned: deeper than the prefix is nothing
 *    the app publishes, and the corpus must still see it. Nor is an exact registered route
 *    like '/security/audit' — it resolves, so it never reaches a 404 handler; as middleware,
 *    ask the router itself.
 *  - A parameter-first route ('{path}', ':controller') contributes nothing. Its segment would
 *    own every path and switch the sensor off — an oracle hardcoded to true.
 *
 * Hand it the URI patterns as the RUNTIME router knows them, never a parse of the route files:
 * a static parse cannot see group prefixes, so it lists 'ping' for a route registered under
 * 'api' and grants ownership of a /ping the app does not publish (measured: 112 parsed vs 83
 * real). A callable is enumerated lazily, on the first check that needs it, because a
 * framework's router is still empty while its config is being read.
 *
 * Framework-free on purpose — the router glue is the host's two lines. Laravel:
 *
 *     RouteOracle::bareSegments(static function () {
 *         foreach (app('router')->getRoutes() as $route) { yield $route->uri(); }
 *     })
 *
 * 7.3-clean: no arrow functions, no union types, no str_starts_with().
 */
final class RouteOracle
{
    /**
     * @param iterable<string>|callable $routeUris route URI patterns as the router lists them
     *        ('security/audit', '/', '{path}', 'api/v1/users/{id}'), or a callable returning
     *        them, enumerated once on first use
     * @return callable fn(string $method, string $path): bool — the own_routes oracle. The
     *         method is accepted for the contract and ignored: ownership here is path-shaped.
     */
    public static function bareSegments($routeUris): callable
    {
        if (is_array($routeUris) || $routeUris instanceof Traversable) {
            $segments = self::segmentsOf($routeUris);
            $provider = null;
        } elseif (is_callable($routeUris)) {
            $segments = null;
            $provider = $routeUris;
        } else {
            throw new InvalidArgumentException(
                'funnypot: RouteOracle::bareSegments() takes the route URI patterns as an array, a '
                . 'Traversable, or a callable returning one — as the runtime router lists them.'
            );
        }

        return static function ($method, $path) use ($provider, &$segments) {
            $bare = self::bareSegment((string) $path);
            if ($bare === null) {
                return false;
            }
            if ($bare === '') {
                return true;
            }

            if ($segments === null) {
                $listed = self::segmentsOf(call_user_func($provider));
                // An empty router is the config-time router, not the app's. Answer this
                // request without remembering, so the first request after boot does not
                // decide every later one.
                if ($listed === array()) {
                    return false;
                }
                $segments = $listed;
            }

            return isset($segments[$bare]);
        };
    }

    /**
     * The lower-cased first segment of every literal route, as a lookup.
     *
     * @param mixed $uris
     * @return array<string,true>
     */
    private static function segmentsOf($uris): array
    {
        if (!is_iterable($uris)) {
            throw new InvalidArgumentException(
                'funnypot: RouteOracle::bareSegments() expected a list of route URI patterns, got '
                . gettype($uris) . '.'
            );
        }

        $set = array();
        foreach ($uris as $uri) {
            if (!is_string($uri)) {
                throw new InvalidArgumentException(
                    'funnypot: RouteOracle::bareSegments() wants route URI patterns as strings — map '
                    . 'your router\'s route objects to their URI first.'
                );
            }

            $uri = trim($uri, '/');
            $slash = strpos($uri, '/');
            $first = $slash === false ? $uri : substr($uri, 0, $slash);

            // The root route is owned regardless; a placeholder must never own its literal text.
            if ($first === '' || $first[0] === '{' || $first[0] === ':') {
                continue;
            }

            $set[strtolower($first)] = true;
        }

        return $set;
    }

    /**
     * The one segment of a bare request path, lower-cased: '' for the root, null when the
     * path is deeper than one segment. Query and fragment are dropped; slashes at either end
     * are not part of the segment.
     */
    private static function bareSegment(string $path): ?string
    {
        $cut = strpos($path, '?');
        if ($cut !== false) {
            $path = substr($path, 0, $cut);
        }
        $cut = strpos($path, '#');
        if ($cut !== false) {
            $path = substr($path, 0, $cut);
        }

        $path = trim($path, '/');
        if ($path === '') {
            return '';
        }

        return strpos($path, '/') === false ? strtolower($path) : null;
    }
}
