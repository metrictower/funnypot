<?php

declare(strict_types=1);

namespace Funnypot\Sensor;

/**
 * Paths a site is asked for whether or not it has them.
 *
 * Browsers, mobile platforms, password managers and standards-following crawlers fetch these
 * UNPROMPTED — with no link on the page and no user action — so a 404 for one is not evidence
 * of anything. They are in the nuclei corpus because scanners request them too, which is
 * exactly why a bare corpus match cannot be the report signal.
 *
 * Rules for this list, and they matter:
 *
 *  - EXACT, root-anchored paths only. Never a prefix or substring rule: the corpus contains
 *    /actuator/favicon.ico and /web/manifest.json, and both are genuine probes.
 *  - Unprompted only. If a page has to link it, the request carries a Referer and the path
 *    exists, so it never reaches here.
 *  - Append-only, hand-curated. It costs 10 of the corpus's 5,196 route keys, and the whole
 *    value of the approach is that it stays that small.
 *
 * Deliberately excluded: /.well-known/openid-configuration (no browser fetches it unprompted,
 * and it is a real recon target) and /crossdomain.xml (same).
 *
 * This is the interim home. It moves to funnypot-core as resources/ambient-paths.php with a
 * compile-time `amb=1` stamp, alongside the `sig=1` stamp core already carries for `/`.
 */
final class AmbientPaths
{
    /** @var string[] */
    private const PATHS = array(
        '/favicon.ico',
        '/robots.txt',
        '/sitemap.xml',
        '/sitemap_index.xml',
        '/manifest.json',
        '/site.webmanifest',
        '/browserconfig.xml',
        '/apple-touch-icon.png',
        '/apple-touch-icon-precomposed.png',
        '/humans.txt',
        '/ads.txt',
        '/app-ads.txt',
        '/.well-known/security.txt',
        '/.well-known/change-password',
        '/.well-known/apple-app-site-association',
        '/.well-known/assetlinks.json',
        '/.well-known/dnt-policy.txt',
    );

    /**
     * @param string[] $extra
     * @param string[] $drop
     * @return array<string,true> lookup keyed by path
     */
    public static function lookup(array $extra = array(), array $drop = array()): array
    {
        $paths = array_merge(self::PATHS, $extra);
        $set = array();
        foreach ($paths as $path) {
            $set[$path] = true;
        }
        foreach ($drop as $path) {
            unset($set[$path]);
        }

        return $set;
    }
}
