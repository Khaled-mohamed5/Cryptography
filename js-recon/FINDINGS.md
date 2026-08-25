# Bentley Motors — JS attack-surface triage

Derived from the katana crawl of `https://www.bentleymotors.com` (277 URLs, 18 hosts,
77 unique JS assets). Nothing here is a confirmed vulnerability — these are the leads
worth spending time on, ordered by expected payoff. Run `./run-all.sh` first, then work
this list against `out/report.md`.

Program context: Intigriti private program, Tier 2 / Tier 3 payouts, currently in BETA.
Confirm each host against the program's RoE before testing — several of the hosts below
are third-party SaaS and are commonly excluded.

---

## P1 — Runtime clientlib path construction on `support.bentleymotors.com`

katana emitted this as a URL:

```
https://support.bentleymotors.com/etc/clientlibs/bentley_v2/','
```

That trailing `','` is not a path. It is the crawler capturing a **JavaScript string
concatenation** — the source almost certainly looks like:

```js
loadScript('/etc/clientlibs/bentley_v2/' + name + '.min.js')
```

So a clientlib path is being **built at runtime from a variable**. If `name` derives from
anything reachable by an attacker (URL param, hash, locale, `dataVersion`, a postMessage),
this is script injection with full same-origin execution.

Where to look, in order:
- `bentley.motors.setup.lc-3.55.0-8a0c973a-lc.min.js`
- `bentley.motors.apps.v2.3.55.0-8a0c973a.min.js`
- `bentley.motors.lib.header.lc-*.js` / `bentley.motors.lib.footer.lc-*.js`

Grep the analyzer output for the `dynload` section — it flags exactly this pattern.

---

## P1 — AEM component template literals reaching HTML sinks on `www`

The crawl leaked eight **unrendered ES6 template placeholders** as if they were URLs:

```
/etc.clientlibs/bm-platform/bmcom/clientlibs/${m.cta.href}
/etc.clientlibs/bm-platform/bmcom/clientlibs/${m.background.srcset}
/etc.clientlibs/bm-platform/bmcom/clientlibs/${m.mainMedia.srcset}
/etc.clientlibs/bm-platform/bmcom/clientlibs/${m.mainMedia.imageRef}
/etc.clientlibs/bm-platform/bmcom/clientlibs/${m.thumbnail.srcset}
/etc.clientlibs/bm-platform/bmcom/clientlibs/${e.videoSrc}
/etc.clientlibs/bm-platform/bmcom/clientlibs/${a}
/etc.clientlibs/bm-platform/bmcom/clientlibs/${e}
```

These come from clientlib JS building markup like
``` `<a href="${m.cta.href}">…` ``` and ``` `<img srcset="${m.background.srcset}">` ```
and then assigning it to `innerHTML`. `m` is the AEM component model, hydrated from a
`.model.json` / `data-*` attribute.

Two questions to answer:
1. Does any field of `m` originate from a **request-controlled** value (query param, AEM
   suffix, selector, hash) rather than only from authored content? If yes → DOM XSS.
2. `${m.cta.href}` lands inside an `href`. Even if authored-only, check whether a
   `javascript:` scheme survives — combined with any authoring or content-injection
   primitive that becomes stored XSS.

Priority bundles:
`bm-m-cta-teaser`, `bm-m-card-wall`, `bm-m-media-gallery`, `bm-m-full-width-slider`,
`bm-m-content-tiles`, `bm-m-article-teaser`, `bm-m-sound-display`, `bm-m-header`.

The analyzer's `template literal HTML` sink rule plus the `sources` correlation is built
for this case.

---

## P1 — AEM suffix / selector routing on the lead-capture forms

```
/en/pages/enquire-to-buy.suffix.html/byDOI=continental-gtc~2Fs.html
/en/pages/request-test-drive.suffix.html/byDOI=continental-gt~2Fspeed~2Fhybrid.html
/en/pages/brochure.suffix.html/byDOI=flying-spur~2Fs.html
/en/misc/car-configurator.html/models/Flying_Spur/new_flying_spur_v8_hybrid_2027
/en/apps/dealer-locator.html/country/AU-Australia
```

`.suffix.html/…` is Sling selector + suffix, and `~2F` is an escaped `/` — so the
application is already doing its own encode/decode dance on a request-controlled path
segment. These are the highest-yield spots on an AEM site:

- **Reflected XSS in the suffix** — is `byDOI=` echoed into the page or into a JS
  variable? Try `…suffix.html/byDOI="><img src=x onerror=alert(1)>.html`.
- **Traversal via the `~2F` decode** — `byDOI=..~2F..~2Fetc` and double-encoded variants.
  If `~2F` is decoded *after* a path check, the check is bypassable.
- **Dispatcher cache poisoning** — the suffix is part of the cache key on disk. Unusual
  suffixes that still return 200 and get cached are a poisoning primitive.
- `dealer-locator.html/country/AU-Australia` clearly feeds a client-side app; trace where
  `country` lands in the locator JS.

---

## P1 — `bfsaccount.americas.bentleymotors.com` (Bentley Financial Services portal)

Highest-value host in the whole crawl: it is an authenticated **financial account portal**,
so anything there is Critical/Exceptional tier rather than Low.

Stack recovered from asset paths:

```
/Content/Env/83/scripts/Consumer/angular.min.js?v=1.0.9714.35807
/Content/Env/83/scripts/Consumer/angular-{material,messages,aria,animate}.min.js
/Content/LoanService/bundle.js?v=1.0.9714.35807
/Content/Bentley/AutoService/client.js?v=1.0.9714.35807
/Content/static_wdp.js
```

- **AngularJS 1.x, end-of-life.** No security support since Jan 2022. Any user input that
  reaches `{{ }}` interpolation is client-side template injection; on 1.6+ the sandbox is
  gone entirely, so CSTI is a direct path to XSS. Hunt `$sce.trustAsHtml`, `ng-bind-html`,
  `$compile(`, and `ng-include` with a dynamic src.
- **`Env/83` is a build/environment counter.** Try neighbouring values (`Env/82`, `Env/84`,
  and much lower) — an older or staging build left served is both an info leak and often
  ships an unminified bundle or a source map.
- `?v=1.0.9714.35807` is an ASP.NET assembly version → confirms .NET MVC and gives you a
  precise build to fingerprint.
- `LoanService/bundle.js` and `AutoService/client.js` carry the business logic. Extract
  every API route from them and look for object identifiers in request paths — an IDOR on
  a loan or service record here is the single best finding available on this program.

Routes already visible: `/ServiceLanding`, `/ContactUs`, `/AccessibilityStatement`,
`/Privacy`, `/LegalNotice`.

---

## P2 — `careers.bentleymotors.com` (SAP SuccessFactors RMK / Jobs2Web)

```
/js/override.js?locale=en_GB&i=1637940370
/platform/js/localized/strings_en_GB.js?h=6ef0353d
/platform/js/jquery/jquery-migrate-1.4.1.js
/platform/bootstrap/3.4.8_NES/js/lib/dompurify/purify.min.js
/services/rss/category/?catid=4803501
```

- `jquery-migrate-1.4.1` means a **jQuery 1.x/2.x codepath is still live** →
  CVE-2020-11022 / CVE-2020-11023 (`htmlPrefilter` XSS) and CVE-2019-11358 (prototype
  pollution). Pull the real jQuery version from its banner and confirm.
- `purify.min.js` — read the version banner. Old DOMPurify has published mXSS bypasses,
  and it is being used here precisely because untrusted HTML is rendered somewhere.
- `override.js?locale=…` is a **customer-controlled override script** and `locale` is a
  parameter. Check whether `locale` selects a server-side path (traversal) or is reflected.
- `strings_en_GB.js` is a locale-keyed path → try traversal and non-existent locales.
- `/services/rss/category/?catid=4803501` is an **unauthenticated numeric-ID endpoint**.
  Enumerate `catid` for non-public categories, and test parameter reflection into the XML
  (unencoded reflection into RSS renders as XSS in some contexts).

⚠️ This is SAP-operated infrastructure. Check the RoE — third-party SaaS is usually
out of scope even on the target's own domain.

---

## P2 — `virtualtours.bentleymotors.com`

```
/js/jquery.i18n.properties.min.js
/js/{config,languageConfig,manager,modalManager,devices,ga_manager_free,om}.js
/indexSelf.html?1680190
```

- **`jquery.i18n.properties`** builds a fetch path from the language name:
  `path + name + '_' + lang + '.properties'`. If `lang` comes from the URL (very common —
  and `languageConfig.js` exists right next to it), that is arbitrary path fetch on the
  origin, and the loaded values get interpolated into the page. Both a file-read and an
  injection primitive. This is the single most promising file on the host.
- `indexSelf.html?1680190` — a bare numeric query with no key, i.e. a tour ID. Enumerate:
  unpublished or internal tours (factory areas, pre-release models) are a realistic
  sensitive-data finding on a manufacturer.
- `config.js`, `manager.js`, `om.js` are small hand-written files, not vendor bundles —
  disproportionately likely to hold hardcoded keys and unguarded DOM sinks.

---

## P2 — Internal macro-enabled spreadsheets on the CDN

```
https://cdn.bentleymotors.com/downloads/en/bm/doc/4th_Package_2018_1832_FM_081025_1_4EYE_check_by_TR.xlsm
https://cdn.bentleymotors.com/downloads/en/bm/doc/Bentley_3rd_Package_2017_1154_FM_JK_draft_170624.xlsm
```

These filenames are internal-process artefacts, not customer-facing documents:
`4EYE check by TR` is a four-eyes review sign-off with someone's initials, `FM_JK_draft`
likewise, plus package numbers and internal date codes. `.xlsm` means macros are enabled.

Worth doing:
1. Download and inspect for internal PII, supplier/pricing data, and any credentials or
   UNC paths inside the VBA project.
2. The naming scheme is **guessable** — try `1st_Package`, `2nd_Package`, `5th_Package`,
   other years and other initials. A predictable-path document store is a much stronger
   report than two stray files.

Note that `/content/dam/…` is served publicly on `www` too (the GTM script is fetched from
`/content/dam/bm/websites/GTM_script_KGXT2TF2.js`), so DAM enumeration is in play as well:
`/content/dam/bm/websites/{kr,cn,tier2,…}/`.

---

## P3 — `/.rum/` origin proxy (Adobe Helix RUM)

```
https://www.bentleymotors.com/.rum/@adobe/helix-rum-js@%5E2/dist/micro.js
https://au.bentleymotors.com/.rum/@adobe/helix-rum-js@%5E2/dist/micro.js
```

The origin is serving an **npm package path**, semver range and all (`%5E2` is `^2`), from
its own domain. That means something upstream resolves that spec and proxies the bytes back
same-origin.

Test whether the package name is constrained. If `/.rum/@anything/anything@1/dist/x.js`
also proxies, an attacker can serve arbitrary JavaScript **from the bentleymotors.com
origin**, which defeats CSP and any origin-based trust. Worth testing carefully — this is
the highest-impact lead in the P3 group if it holds.

---

## P3 — First-party GTM containers

```
GTM-KGXT2TF2   (www + kr)
GTM-NBP2SMP    (cn)
GTM-P4L69Q5    (au / tier2)
```

Pull each container (`https://www.googletagmanager.com/gtm.js?id=GTM-KGXT2TF2`) and read
its **Custom HTML tags**. The recurring bug: a tag writes a `dataLayer` value into
`document.write` or `innerHTML`, and some `dataLayer` value is seeded from a URL parameter
→ reflected DOM XSS that lives in the tag manager rather than the site code. Also scan the
container for third-party keys.

---

## P3 — Selector-based cache deception on `support.bentleymotors.com`

```
/global/en.js_config.js?dataVersion=2025-12-15T16:27:50.106+01:00
/global/en.css_overlay.css?dataVersion=…
/jp/en/tools/tag_manager.data.js?dataVersion=…
```

`en.js_config.js` is AEM page `en` with selector `js_config` and extension `js` — arbitrary
selectors are being served with arbitrary content types. Test `/global/en.<random>.js` and
`/global/en.<random>.css`: if unknown selectors return 200 and are cacheable, you have a
cache-deception primitive (and possibly a way to get an authenticated page cached publicly).

Same question for every cache-buster in the crawl — `?lastmodifiedat=`, `?dataVersion=`,
`?h=`, `?v=`, `?i=` — are any of them **unkeyed** at the CDN? Unkeyed query params are the
standard web-cache-poisoning entry point.

---

## P3 — Smaller items

- `https://au.bentleymotors.com/www.afca.org.au` — an authored link missing its scheme, so
  it resolves against the origin. Harmless by itself, but it proves href values flow from
  authored content into the DOM without validation. Ties back to `${m.cta.href}`.
- `https://locator.bentleymotors.com/en_gb/?utm_source:Bentleymotors.com` — malformed param
  (`:` instead of `=`). The locator app is a map front-end; check its JS for an unrestricted
  Google Maps API key (no HTTP-referrer restriction = billable abuse; usually Low, sometimes
  accepted).
- `/en/misc/car-configurator.html/select/bentayga/bentayga_speed%20` — a trailing `%20`
  survived into a live path, i.e. the suffix is not normalised. Feeds the P1 suffix work.

---

## Suggested order of work

1. `./run-all.sh` — and check the **source map** step first. If `bfsaccount` or `support`
   ship a `.map`, you get the original application source and everything below gets easier.
2. `bfsaccount` bundles → API routes and object identifiers (best payoff).
3. The `support` dynamic clientlib loader (P1).
4. `${m.*}` template sinks in the `www` clientlibs (P1).
5. AEM suffix injection on the four form pages (P1).
6. Everything else.

## Hosts deliberately excluded from `scope.txt`

`shop.bentleymotors.com` is Shopify-hosted (`/cdn/shop/t/9/…`) — third-party SaaS,
essentially always out of scope. Add it only if the RoE explicitly includes it.
Verify `careers.` (SAP) and `bfsaccount.` (financial partner) against the RoE too.
