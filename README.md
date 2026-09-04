# funnypot 🍯

[![Docs](https://img.shields.io/badge/docs-funnypot.org-f46800.svg)](https://funnypot.org/packages/funnypot/)

> **Not sure you're in the right place?**
> - Want a ready-to-run **honeypot box** to deploy → [funnypot-app](https://github.com/metrictower/funnypot-app)
> - Protecting a **Laravel** app → [funnypot-laravel](https://github.com/metrictower/funnypot-laravel)
> - Protecting a **WordPress** site → [funnypot-wordpress](https://github.com/metrictower/funnypot-wordpress)
> - Adding scanner detection + IP reporting to **any PHP app** → funnypot **← you are here**
> - Embedding just the deception/detection **engine** → [funnypot-core](https://github.com/metrictower/funnypot-core)
> - Querying / reporting to the **IP-reputation service** from code (the SDK) → [funnypot-mainnet-client](https://github.com/metrictower/funnypot-mainnet-client)
> - Building on the low-level **decision/policy engine** → [funnypot-policy](https://github.com/metrictower/funnypot-policy)

**Early days.** Published and tagged, but the API is deliberately small and will still move — pin a
caret range (`^0.5`) rather than tracking a branch. **0.4 rewrote the whole surface** —
`inspect()`/`reportable()`/`min_severity` are gone; see *What the Assessment will not let you do*.
**0.5 reshapes the `Judge` seam** — `judge()` takes a `JudgeContext`, `check()` takes the client IP,
the `Assessment` can say `shouldDeceive()`, and the ambient and honeypot guarantees now hold under a
Judge; see *Bringing your own Judge*.

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
use Funnypot\Sensor\Funnypot;
use Funnypot\Core\RequestContext;

$funnypot = Funnypot::fromArray([
    'base_url'      => 'https://mainnet.example',
    'key'           => getenv('MAINNET_KEY'),
    'self_ips'      => ['203.0.113.7'],          // this host's own public addresses
    'intel_db_path' => '/var/lib/funnypot/intel.sqlite',

    // REQUIRED. Does this path resolve to a route your app actually serves?
    'own_routes'    => function ($method, $path) use ($router) {
        return $router->has($method, $path);
    },
]);

// No I/O — safe inline on the request path. The default rules ignore the IP; a Judge needs it.
$check = $funnypot->check(RequestContext::fromGlobals(), $clientIp);

if ($check->shouldReport()) {
    $funnypot->report($clientIp, $check);   // enqueues only, never blocks
}
if ($check->shouldBlock()) {
    http_response_code(403);
    exit;
}
```

Then, **out of band** — cron, scheduler, worker, never a web request:

```php
$funnypot->drain();   // opens sockets; this is where reports actually get sent
```

That is the whole integration. Two questions, two answers. There is no severity floor to tune and
no anomaly threshold to pick, because neither of those works — see below.

## Four things worth knowing

**Declare your routes, or you report your own users.** `own_routes` is required for the same
reason `key` is: without it the package silently does the wrong thing. The nuclei corpus contains
`/login`, `/admin`, `/register` and `/index.php` precisely *because* real applications have them —
that is what scanners go looking for — so core cannot know yours are genuine unless you say so.
Measured before it was required: a real Chrome browser was reportable on **8 of 10** ordinary
application routes, `/login` and `/index.php` among them at `critical`.

If you mount `check()` inside your 404 / NotFound handler, your framework has already ruled that
nothing reaching it is a real route. Say so explicitly:

```php
'own_routes' => Funnypot::ONLY_ON_404,
```

**A corpus match is not a scanner, and neither severity nor anomaly separates them.** The corpus
carries technology-fingerprint templates next to exploit ones, so ordinary unprompted browser
requests match: `/robots.txt` and `/manifest.json` are `medium`, `/favicon.ico` and `/sitemap.xml`
are `info`.

Two axes were measured and both were rejected:

- **Severity is anti-correlated with benignness** at the top of the traffic distribution. `/` is
  `critical` (1,590 templates), so are `/index.php` and `/login`, because the corpus piles its most
  and most-severe templates onto the paths everyone requests. Meanwhile `/.git/config` is `medium`
  and `/actuator/env` is `low`, and both are real probes.
- **Anomaly is path-blind.** 15 paths × 8 client shapes produced an identical anomaly row for every
  path — the same client scores the same on `/robots.txt` as on `/.env`. And the bands interleave
  once you include legitimate non-browser clients: UptimeRobot 24 > Googlebot 19 > **curl 14**.
  There is no cut point to choose.

So the judgement turns on the **path property** plus named signal flags. `Assessment::AMBIENT`
covers the ~17 exact paths a site is asked for whether or not it has them, and it costs 10 of the
corpus's 5,196 route keys. Tune it with `ambient_extra` / `ambient_drop`; replace the judgement
with a `Judge` — which keeps the ambient guarantee; see *What survives a Judge*.

**One benign report is worse than no report.** The mainnet dedup key is the IP alone, marked at
enqueue, over a 24-hour window. A benign `/robots.txt` report consumes that IP's slot, and the same
IP's real probe two hours later is silently dropped as a duplicate. False positives do not merely
add noise — they spend the sensor's budget on visitors and drop the attacks. That is why the
defaults here are conservative, and why one false negative is stated rather than papered over: a
scanner that spoofs a complete Chrome header set and touches only ambient paths is not reported.
Forged Chrome measures anomaly 0 even on `/.env`, so no anomaly design catches it either.

**It refuses to start half-configured.** The underlying SDK is fail-safe by design and skips
silently when the key, `self_ips`, or the queue path is missing — which for an embedder reads as
"installed and working" until someone notices no reports ever arrived. `fromArray()` turns each of
those into a constructor error instead.

## Silencing a noisy template

When one template turns out to be a false positive on your site, you don't have to turn the sensor
off — silence just that template with `ignore_templates`. The id to name is already in every report:
`Assessment::templateIds()` lists the templates that drove a classification, so a false-positive log
line hands you the exact id.

```php
$detector = Detector::fromArray([
    'own_routes'       => Funnypot::ONLY_ON_404,
    'ignore_templates' => ['laravel-telescope', 'miscellaneous'],   // template ids AND tags
]);
```

An ignored template contributes **no evidence**: a request whose only matching templates are listed
classifies `clean` and is never reported, while a request that also matches a template you did *not*
list is still reported on that remaining one (drop-from-evidence). Both ids and tags are accepted, so
a whole noisy tag can go in one entry.

This is the template-side lever; `ambient_extra` / `ambient_drop` are the path-side one. Reach for
`ignore_templates` when a specific template misfires; reach for the ambient lists when a whole path
is browser chatter. (It is unrelated to core's serving-side `exclude`, which a detection sensor never
serves through.)

## Already have a queue?

Mainnet delivery here rides a bundled SQLite queue. That is the right default for a framework-free
app and the wrong one for Laravel or Symfony: N workers on an ephemeral container filesystem
fragment the dedup state and the daily counter per worker, and lose both on redeploy.

`Detector` is the judgement with no reporting attached — same `check()`, same `Assessment`, and it
needs no mainnet key and no queue path because `check()` does no I/O (and, under the default rules,
keeps no state):

```php
use Funnypot\Sensor\Detector;

$detector = Detector::fromArray(['own_routes' => Funnypot::ONLY_ON_404]);

$check = $detector->check($request);
if ($check->shouldReport()) {
    MyReportJob::dispatch($clientIp, $check->toArray());   // your queue, your delivery
}
```

`Funnypot` is a `Detector` plus delivery, and `$funnypot->detector()` hands back the inner one.

## Operating modes

Two independent choices: **where** it runs, and **what you do** with the answer.

### Where — the mount point

| mount | config | sees |
|---|---|---|
| **404 / NotFound handler** | `'own_routes' => Funnypot::ONLY_ON_404` | only unmatched requests |
| **pre-request middleware** | `'own_routes' => fn($m, $p) => $router->has($m, $p)` | all traffic, before routing |

The mount point is expressed *through the route oracle*, and that is why `own_routes` is required.
In a 404 handler the framework has already ruled nothing reaching you is real, so `ONLY_ON_404` is
a true statement. As middleware you see your own `/login`, and without a real oracle funnypot
reports your own users — measured at 8 of 10 ordinary routes.

### What — the posture

`check()` returns a verdict; the host decides. Nothing here needs configuration:

| posture | how |
|---|---|
| **log only** | read `$check->toArray()`, ignore both verbs. Good for a trial run |
| **detect + report** | act on `shouldReport()` |
| **block (WAF)** | act on `shouldBlock()` |
| **honeypot / deceive** | `'profile' => PROFILE_HONEYPOT`, serve your own decoy — or a `Judge` that returns a fake, and act on `shouldDeceive()` |

**Log-only needs no feature and no flag** — it is what you get by not acting on the verbs. That is
the recommended way to start: run funnypot beside whatever you have, compare the two, and only then
give it authority.

### Acting on a scripting user agent — opt-in, and off by default

```php
'act_on_scripting_uas' => true,     // default false
```

**The path is the signal; the user agent is weak corroboration.** An exploit against `/wp-admin/`
or a fetch of `/.env` is malicious whether it arrives from Chrome, curl or Googlebot — and a plain
`curl` request to an ordinary page is not an attack.

So by default a scripting UA (`curl`, `python-requests`, `wget`, `Go-http-client`) changes nothing:
the same path returns the same verdict whoever asks. Only **named scanner tools** (`nikto`,
`sqlmap`, `zgrab`, `nuclei`) act on their own.

Turn this on and a scripting UA additionally makes an **ambient** path reportable — with a Judge as
without one. In the built-in rules it never causes blocking, at any setting. A Judge keeps its own
authority to block on your declared routes (see *What survives a Judge*); an ambient path is never
blocked either way.

**Think hard before enabling it on an API host.** `curl` and `python-requests` against `/api/` are
the *expected* clients — they are the integrations your app exists to serve. The signal is really
path-dependent, not client-dependent: the same UA is unremarkable on an API and odd on a login
form, and treating it as a property of the client alone is what produces the false positive.

### Bringing your own Judge

`'judge' => $judge` replaces the default judgement with a `Funnypot\Sensor\Judge` — the seam
`funnypot-policy` plugs into. It is handed the core `Verdict`, the `RequestContext`, and a
`JudgeContext` carrying the three things neither of those has: `posture()` (`PROFILE_APP` /
`PROFILE_HONEYPOT`), `ip()`, and `profile()` — core's `SiteProfile`, so `hasRoute($method, $path)`
answers with *your* `own_routes` oracle rather than an empty one.

```php
public function judge(Verdict $verdict, RequestContext $request, JudgeContext $context): array
{
    // ...
    return ['report' => true, 'block' => false, 'reason' => 'deceive', 'fake' => $fakeResponse];
}
```

Three things follow from a Judge being there:

- **Pass the client IP to `check()`.** Core's `RequestContext` is IP-blind by design, so a Judge
  gets the address only from `check($request, $clientIp)`. Without it the check **fails open** —
  `report=false`, `block=false`, `reason='no-client-ip'` — and the Judge is not called. It does
  not fall back to the default rules: those are *stricter* than a policy carrying an allowlist,
  so that fallback would bypass the operator's own exemptions.
- **`fake` is the deceive channel.** Return an object (funnypot-policy's `FakeResponse`, or your
  own) and the host reads it back as `$check->shouldDeceive()` / `$check->fake()` and serves it in
  place of the real response. A ruling that carries a fake never blocks, whatever it said in
  `block` — a block is a tell, and deceive exists to avoid one. The default rules never deceive.
- **`check()` is only as pure as the Judge.** The default rules keep no state; funnypot-policy's
  Judge reads and writes its store on every ruling. Call `check()` once per request, and use
  `Detector::checkPure()` — the default rules, Judge or not — anywhere the same request is seen a
  second time. `MainnetObserver` already does.

#### What survives a Judge

A Judge replaces the judgement, not the guarantees behind it. Its ruling passes through one clamp
on the way out — `Detector::clamp()`, the single list, so the next guarantee is added there rather
than rediscovered — and every entry is a **ceiling**: it can clear a verb the ruling set, never set
one the ruling cleared. A Judge that says no — an allowlist, a dry run — is always honoured.

| whatever the ruling said | the `Assessment` says |
|---|---|
| block, with a `fake` | `shouldBlock()` false — a block beside a fake is a tell |
| block, under `PROFILE_HONEYPOT` | `shouldBlock()` false — a honeypot that blocks has announced itself |
| block, on an `ambient` path | `shouldBlock()` false — refusing `/robots.txt` costs you a crawler |
| report, on an `ambient` path | `shouldReport()` true only where the default rules would say so: a named scanner UA, a scripting UA under `act_on_scripting_uas`, or `PROFILE_HONEYPOT` off `/robots.txt` |
| report, on a `clean` / `suspicious` request | `shouldReport()` false — a declared route is your own traffic |

The ambient row is the one that matters. Ambient is the *sensor's* classification — core's
`Verdict` says `scanner-probe` for `/robots.txt` — so the obvious Judge, "report anything not
clean", reports every browser's favicon fetch, and one such report spends that IP's 24-hour mainnet
dedup slot (see *One benign report is worse than no report*). A Judge cannot see the ambient list,
so it cannot avoid this itself; the sensor does it for every Judge.

What a Judge keeps is everything on your own routes. On a declared route it is the WAF — the sensor
cannot know whether it blocked for a brute-force counter, a rate limit or a reputation hit — so
`block` there is the Judge's alone, from a browser and from `curl` alike. `reason()` is always the
Judge's own label, clamped or not.

### What is NOT available yet

The default rules are **stateless** — each request is judged on its own. What funnypot cannot yet do
for a framework-free host is **accumulate across requests**: scores that decay, ban thresholds,
pins, an operator allowlist. That lives in `funnypot-policy` and needs a `StateStore` the Sensor
does not yet ship (FP-0101). Until then, "funnypot as a WAF" means per-request blocking, not
accumulate-and-ban.

`Assessment::score()` already hands you the number to accumulate: a graded `+1` / `+10` / `+100`
on funnypot-policy's own scale (`StateStoreInterface::decayScore`), derived from `kind()` so it
means the same thing whether or not a `Judge` is configured. A host that wants banning today can
feed it into its own store against `funnypot-policy` directly; Funnypot itself just doesn't wire
that loop up for you yet.

## The two profiles

```php
'profile' => Funnypot::PROFILE_APP,        // default: a real site with real visitors
'profile' => Funnypot::PROFILE_HONEYPOT,   // nothing on this host is real
```

The profile moves `shouldReport()` / `shouldBlock()` and **nothing else**. Evidence on the
`Assessment` — `kind()`, `severity()`, `score()`, `anomaly()`, `signals()`, `templateIds()`,
`tags()` — is always populated either way, so a honeypot logs the same row a real app would.

| `kind()` | report, APP | report, HONEYPOT | block, APP |
|---|---|---|---|
| `clean` | no | no | no |
| `ambient` | only with a scanner UA | yes, except `/robots.txt` | no |
| `scanner-probe` | yes | yes | yes |
| `attack-class` | yes | yes | yes |

`shouldBlock()` is always false under `PROFILE_HONEYPOT`, with or without a Judge: a honeypot that
blocks has told the attacker it detected them. Ambient paths are never blocked even from a scanner,
with or without a Judge — refusing a `/robots.txt` fetch gains nothing and costs you a crawler the
day the UA match is wrong.

**`/robots.txt` is the one path exempt from `PROFILE_HONEYPOT`'s otherwise-unconditional ambient
reporting.** A well-behaved crawler is expected to fetch it even on a box with nothing real behind
it — that is what the file is for — so reporting compliant behaviour earns nothing. Every other
ambient path still reports under `PROFILE_HONEYPOT`.

## What the Assessment will not let you do

The one mistake this shape exists to prevent is reaching past the verbs for something that reads
like state:

```php
if ($check->matched) { … }      // LogicException, with an explanation
$funnypot->report($ip, $detection);   // TypeError — report() takes an Assessment
```

Both fire in coercive mode too. `inspect()`, `reportable()` and `min_severity` are gone rather than
deprecated — `reportable()` was measured returning true for a real browser on `/`, `/login` and
`/index.php`, so leaving it reachable was the larger risk. Upgrading is a fatal at composer-update
time, never a silent over-report.

## Serving fakes too

If you also want core's deception responses, `Reporting\MainnetObserver` implements core's
`Observer` seam so detections on the `respond()` path get reported:

```php
use Funnypot\Sensor\Reporting\MainnetObserver;

$observer = new MainnetObserver($funnypot, static function () use ($clientIp) { return $clientIp; });
$engine   = \Funnypot\Core\Honeypot::default(null, $observer);
```

Core calls an Observer only on the `respond()` path, so detect-only integrations should stay with
`check()` / `report()` at their own call site. The observer re-runs the **default rules**
(`Detector::checkPure()`) rather than reporting on the `Detection` core hands it: a Detection
carries no classification, so reporting on one means reporting on a bare corpus match. The
re-check costs a few microseconds. It deliberately never re-runs a configured `Judge` — this hook
fires after your own `check()` for the same request, and a stateful Judge run twice scores the
actor twice.

## Namespace

`Funnypot\Sensor\` — because that is what this package makes your app: a sensor on the funnypot
network. It watches and it reports. The vocabulary is already load-bearing elsewhere in the family
(the SDK mints a per-sensor UUID, mainnet issues sensor keys), so this package finally matches it.

Every package owns a distinct sub-namespace and **none declares the bare `Funnypot\` root** —
Composer merges identical PSR-4 prefixes into one prefix over several directories and then picks by
autoload registration order. Distinct sub-namespaces make resolution deterministic, because a longer
prefix always wins. `Funnypot\Bundle\` is deliberately left free: to a PHP developer "bundle" means
Symfony, and that is where a future `funnypot-symfony` belongs.

## Test

```bash
composer install
php vendor/bin/phpunit
```
