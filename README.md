# funnypot 🍯

> **Not sure you're in the right place?**
> - Want a ready-to-run **honeypot box** to deploy → [funnypot-app](https://github.com/metrictower/funnypot-app)
> - Protecting a **Laravel** app → [funnypot-laravel](https://github.com/metrictower/funnypot-laravel)
> - Protecting a **WordPress** site → [funnypot-wordpress](https://github.com/metrictower/funnypot-wordpress)
> - Adding scanner detection + IP reporting to **any PHP app** → funnypot **← you are here**
> - Embedding just the deception/detection **engine** → [funnypot-core](https://github.com/metrictower/funnypot-core)
> - Querying / reporting to the **IP-reputation service** from code (the SDK) → [funnypot-mainnet-client](https://github.com/metrictower/funnypot-mainnet-client)
> - Building on the low-level **decision/policy engine** → [funnypot-policy](https://github.com/metrictower/funnypot-policy)

**Skeleton — not yet released.** The API below works but is deliberately small; expect it to move.

The batteries-included entry point: [`funnypot-core`](https://github.com/metrictower/funnypot-core)
detection wired to [`funnypot-mainnet-client`](https://github.com/metrictower/funnypot-mainnet-client)
reporting, for a framework-free PHP app that just wants scanner probes detected and the attacker IP
reported. One `composer require` instead of assembling the two yourself and rediscovering the
invariants.

```bash
composer require metrictower/funnypot
```

PHP 7.3+. Needs `ext-pdo_sqlite` for the bundled report queue and `ext-curl` for delivery.

## Use

```php
use Funnypot\Bundle\Funnypot;
use Funnypot\RequestContext;

$funnypot = Funnypot::fromArray([
    'base_url'      => 'https://mainnet.example',
    'key'           => getenv('MAINNET_KEY'),
    'self_ips'      => ['203.0.113.7'],          // this host's own public addresses
    'intel_db_path' => '/var/lib/funnypot/intel.sqlite',
]);

// On a 404 / unmatched route. Pure, no I/O — safe inline.
$detection = $funnypot->inspect(RequestContext::fromGlobals());

if ($detection->matched) {
    $funnypot->report($clientIp, $detection);   // enqueues only, never blocks
}
```

Then, **out of band** — cron, scheduler, worker, never a web request:

```php
$funnypot->drain();   // opens sockets; this is where reports actually get sent
```

## Three things worth knowing

**Reporting is enqueue-then-drain, and the drain is yours to schedule.** `report()` does no
network I/O. There is no genuinely async HTTP in stock PHP without an event loop — fibers are
cooperative coroutines with no I/O of their own, and the fire-and-forget socket tricks either
fail under TLS or still block — so a queue is the honest seam. If you never call `drain()`,
nothing is ever sent.

**A template match is not, by itself, a scanner.** The nuclei corpus carries technology-fingerprint
templates alongside exploit ones, so ordinary unprompted browser requests match:

| path | severity |
|---|---|
| `/robots.txt` | medium |
| `/manifest.json` | medium |
| `/favicon.ico` | info |
| `/sitemap.xml` | info |
| `/browserconfig.xml` | info |

`reportable()` applies a **severity floor**, defaulting to `high`. That is a stopgap, not a fix:
severity does not cleanly separate benign from hostile in either direction — `/.git/config` is
`medium` and `/actuator/env` is `low`, and both are real probes. What actually separates them is
request *shape*: the same `/robots.txt` scores anomaly 0 from a real browser and 39 from a
scanner. If you need that, drive
[`funnypot-policy`](https://github.com/metrictower/funnypot-policy) rather than this facade's
`reportable()`.

**It refuses to start half-configured.** The underlying SDK is fail-safe by design and skips
silently when the key, `self_ips`, or the queue path is missing — which for an embedder reads as
"installed and working" until someone notices no reports ever arrived. `fromArray()` turns each of
those into a constructor error instead.

## Serving fakes too

If you also want core's deception responses, `Reporting\MainnetObserver` implements core's
`Observer` seam so detections on the `respond()` path get reported:

```php
use Funnypot\Bundle\Reporting\MainnetObserver;

$observer = new MainnetObserver($funnypot, static fn () => $clientIp);
$engine   = \Funnypot\Honeypot::default(null, $observer);
```

Core calls an Observer only on the `respond()` path, so detect-only integrations should stay with
`inspect()` / `report()` at their own call site.

## Namespace

`Funnypot\Bundle\` — deliberately not the bare `Funnypot\` root, which `funnypot-core` already
claims.

## Test

```bash
composer install
php vendor/bin/phpunit
```
