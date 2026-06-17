<?php

return [

    'hsts' => [

        /*
        |--------------------------------------------------------------------------
        | Enable HSTS
        |--------------------------------------------------------------------------
        |
        | Toggle the Strict-Transport-Security header on or off.
        |
        */
        'enabled' => true,

        /*
        |--------------------------------------------------------------------------
        | Max Age
        |--------------------------------------------------------------------------
        |
        | The time, in seconds, that the browser should remember that a site
        | is only to be accessed using HTTPS. Default is 1 year (31536000).
        |
        */
        'max_age' => 31536000,

        /*
        |--------------------------------------------------------------------------
        | Include Sub-Domains
        |--------------------------------------------------------------------------
        |
        | If enabled, the HSTS rule applies to all subdomains as well.
        |
        */
        'include_sub_domains' => true,

        /*
        |--------------------------------------------------------------------------
        | Preload
        |--------------------------------------------------------------------------
        |
        | If enabled, the site can be included in browsers' HSTS preload lists.
        | Only enable this if you are confident all subdomains support HTTPS.
        |
        */
        'preload' => false,

    ],

    'csp' => [

        /*
        |--------------------------------------------------------------------------
        | Enable CSP
        |--------------------------------------------------------------------------
        |
        | Toggle the Content-Security-Policy header on or off.
        |
        */
        'enabled' => env('CSP_ENABLED', true),

        /*
        |--------------------------------------------------------------------------
        | Report Only
        |--------------------------------------------------------------------------
        |
        | When true, uses Content-Security-Policy-Report-Only instead of
        | Content-Security-Policy. Violations are reported but not enforced.
        | Recommended to keep true during initial rollout.
        |
        */
        'report_only' => env('CSP_REPORT_ONLY', true),

        /*
        |--------------------------------------------------------------------------
        | Report URI
        |--------------------------------------------------------------------------
        |
        | Optional endpoint to receive CSP violation reports. If null and
        | `report.register_route` is true, the package's own endpoint path
        | is used automatically.
        |
        */
        'report_uri' => env('CSP_REPORT_URI', null),

        /*
        |--------------------------------------------------------------------------
        | Built-In Violation Report Endpoint
        |--------------------------------------------------------------------------
        |
        | When `register_route` is true, the package registers a POST route at
        | `path` that accepts browser-sent CSP violation reports and writes
        | them to the configured log channel. The route is registered outside
        | the `web` middleware group (no session, no CSRF) and is rate-limited.
        |
        */
        'report' => [
            'register_route' => env('CSP_REPORT_ROUTE', true),
            'path' => env('CSP_REPORT_PATH', '/csp-report'),
            'throttle' => env('CSP_REPORT_THROTTLE', '60,1'),
            'channel' => env('CSP_REPORT_CHANNEL', null),

            /*
            | Persist each violation to the database in addition to the log
            | channel. The package ships a migration that creates the table
            | below (auto-loaded; no publish required). Set `connection` to
            | route writes to a non-default DB.
            */
            'store_in_db' => env('CSP_REPORT_DB', true),
            'table' => env('CSP_REPORT_TABLE', 'csp_reports'),
            'connection' => env('CSP_REPORT_DB_CONNECTION', null),
        ],

        /*
        |--------------------------------------------------------------------------
        | Nonce + 'strict-dynamic'
        |--------------------------------------------------------------------------
        |
        | Strict CSP — Google's recommended pattern for modern apps.
        |
        | When `enabled`, the middleware generates a per-request nonce and
        | appends `'nonce-{value}'` to script-src. Mark trusted inline
        | <script> tags (and any third-party loader you want to trust)
        | with the @cspNonce Blade directive:
        |
        |     <script @cspNonce>...</script>
        |
        | When `strict_dynamic` is also true, `'strict-dynamic'` is added
        | to script-src. Modern browsers then trust any script loaded BY
        | a nonced/hashed script — eliminating the need to maintain a
        | per-vendor origin allowlist for third-party loaders. The origin
        | allowlist still emits, serving as fallback for browsers that
        | don't support strict-dynamic.
        |
        | Important: with strict-dynamic on, EVERY external <script> tag
        | rendered in your views (GTM, HubSpot, etc.) must carry the
        | nonce. Frameworks that emit their own scripts (Livewire 3,
        | Filament 3) auto-detect the nonce from the page when wired up.
        |
        */
        'nonce' => [
            'enabled' => env('CSP_NONCE', true),
            'strict_dynamic' => env('CSP_STRICT_DYNAMIC', true),

            /*
             * When true, the SRI middleware (which already parses every
             * <script> tag in the response) auto-injects nonce="…" on any
             * script tag that doesn't already have one. This catches
             * CMS-rendered raw HTML (e.g. Filament Fabricator `html` blocks
             * that output admin-authored markup via {!! … !!}) without
             * needing per-template @cspNonce annotations.
             *
             * Disable if you render user-generated HTML through {!! !!} and
             * need a strict per-template trust boundary instead.
             */
            'auto_inject' => env('CSP_NONCE_AUTO_INJECT', true),
        ],

        /*
        |--------------------------------------------------------------------------
        | Asset Domain(s)
        |--------------------------------------------------------------------------
        |
        | CDN/origin host(s) serving your assets. When set, each value is
        | automatically appended to script-src, style-src, img-src, font-src,
        | connect-src, and media-src. Leave null if you serve assets only from
        | your own origin.
        |
        | Accepts: null, a single URL string, or an array of URL strings.
        | When provided via env, comma-separate multiple hosts.
        |
        |   'asset_domain' => 'https://cdn.example.com',
        |   'asset_domain' => ['https://cdn.example.com', 'https://bucket.s3.amazonaws.com'],
        |
        | The SRI middleware also reads this value to resolve the 'asset' token
        | in `sri.host_allowlist`, so any host listed here becomes eligible for
        | SRI integrity injection automatically.
        |
        */
        'asset_domain' => env('CSP_ASSET_DOMAIN', null),

        /*
        |--------------------------------------------------------------------------
        | Exclude Paths
        |--------------------------------------------------------------------------
        |
        | Request paths that should NOT receive the CSP header. Useful for
        | admin panels or Livewire endpoints that manage their own assets.
        |
        */
        'exclude_paths' => ['admin', 'livewire'],

        /*
        |--------------------------------------------------------------------------
        | Directives
        |--------------------------------------------------------------------------
        |
        | CSP directive map. Each key is a directive name and each value is an
        | array of sources. The asset_domain is auto-appended to applicable
        | directives at runtime.
        |
        | This is a strict same-origin baseline. To allow third-party origins
        | (Google Tag Manager, HubSpot, Stripe, etc.), run:
        |
        |     php artisan security:install
        |
        | …which adds the right entries per integration. Or hand-edit below.
        |
        */
        'directives' => [

            'default-src' => ["'self'"],

            'script-src' => ["'self'"],

            'style-src' => ["'self'"],

            'img-src' => ["'self'", 'data:'],

            'font-src' => ["'self'", 'data:'],

            'connect-src' => ["'self'"],

            'media-src' => ["'self'"],

            'frame-src' => ["'self'"],

            // Who may embed THIS site in a frame (anti-clickjacking). Note this
            // is only enforced when csp.report_only is false; the X-Frame-Options
            // header below is the actively-enforced equivalent during rollout.
            'frame-ancestors' => ["'self'"],

            'object-src' => ["'none'"],

            'base-uri' => ["'self'"],

        ],

    ],

    'frame_options' => [

        /*
        |--------------------------------------------------------------------------
        | Enable X-Frame-Options
        |--------------------------------------------------------------------------
        |
        | Toggle the X-Frame-Options header on or off. This is the anti-clickjacking
        | control that is honored by browsers regardless of CSP report-only mode,
        | so it remains effective while the CSP frame-ancestors directive is still
        | rolling out in report-only.
        |
        */
        'enabled' => true,

        /*
        |--------------------------------------------------------------------------
        | Value
        |--------------------------------------------------------------------------
        |
        | SAMEORIGIN allows the site to frame its own pages (admin embeds, etc.)
        | while blocking cross-origin framing. Use DENY to forbid all framing.
        |
        */
        'value' => 'SAMEORIGIN',

    ],

    'xcto' => [

        /*
        |--------------------------------------------------------------------------
        | Enable X-Content-Type-Options
        |--------------------------------------------------------------------------
        |
        | Toggle the X-Content-Type-Options: nosniff header on or off.
        |
        */
        'enabled' => true,

    ],

    'permissions_policy' => [

        /*
        |--------------------------------------------------------------------------
        | Enable Permissions-Policy
        |--------------------------------------------------------------------------
        |
        | Toggle the Permissions-Policy header on or off.
        |
        */
        'enabled' => true,

        /*
        |--------------------------------------------------------------------------
        | Directives
        |--------------------------------------------------------------------------
        |
        | Map of feature => allowlist. An empty allowlist ([]) disables the
        | feature entirely. Use ["'self'"] to allow only same-origin, or add
        | trusted origins as quoted strings. Defaults deny sensitive features
        | the site does not use.
        |
        */
        'directives' => [
            'accelerometer' => [],
            'camera' => [],
            'geolocation' => [],
            'gyroscope' => [],
            'magnetometer' => [],
            'microphone' => [],
            'payment' => [],
            'usb' => [],
        ],

    ],

    'sri' => [

        /*
        |--------------------------------------------------------------------------
        | Enable SRI
        |--------------------------------------------------------------------------
        |
        | Toggle Subresource Integrity hash injection on or off. When enabled,
        | the middleware scans HTML responses for <link> and <script> tags
        | and injects integrity + crossorigin attributes for any URL whose
        | path is present in the SRI manifest.
        |
        */
        'enabled' => env('SRI_ENABLED', true),

        /*
        |--------------------------------------------------------------------------
        | Hash Algorithm
        |--------------------------------------------------------------------------
        |
        | The hash algorithm used for SRI. sha384 is the recommended default.
        |
        */
        'algorithm' => 'sha384',

        /*
        |--------------------------------------------------------------------------
        | Manifest Path
        |--------------------------------------------------------------------------
        |
        | Absolute path to the JSON manifest written by `sri:build-manifest`.
        | Lives in bootstrap/cache/ so it ships inside the Vapor code bundle
        | (Lambda cannot read public_path() at runtime).
        |
        */
        'manifest_path' => base_path('bootstrap/cache/sri-manifest.json'),

        /*
        |--------------------------------------------------------------------------
        | Scan Directories
        |--------------------------------------------------------------------------
        |
        | Directories under public/ that `sri:build-manifest` should scan for
        | .js and .css assets. Missing directories are silently skipped.
        |
        */
        'scan_dirs' => ['build', 'css', 'js'],

        /*
        |--------------------------------------------------------------------------
        | App-Host Warm Paths
        |--------------------------------------------------------------------------
        |
        | URL paths served dynamically by the app host (not static files under
        | public/). These are inserted into the manifest as null entries by
        | `sri:build-manifest` and fetched from `app.url` by `sri:warm` at
        | deploy time. Example: Livewire serves its bundled JS through a route.
        |
        */
        'warm_from_app' => [
            '/livewire/livewire.min.js',
            '/livewire/livewire.js',
        ],

        /*
        |--------------------------------------------------------------------------
        | Cache Store
        |--------------------------------------------------------------------------
        |
        | Cache store used as an overlay for hashes populated after deploy by
        | `sri:warm-css`. Null uses the default store. On Vapor this should
        | point at a shared store (redis / dynamodb), not `array` / `file`.
        |
        */
        'cache_store' => env('SRI_CACHE_STORE', null),

        /*
        |--------------------------------------------------------------------------
        | Cache Prefix
        |--------------------------------------------------------------------------
        */
        'cache_prefix' => 'sri:',

        /*
        |--------------------------------------------------------------------------
        | Skip If Integrity Present
        |--------------------------------------------------------------------------
        |
        | When true, tags that already have an integrity attribute (e.g. from
        | an external CDN that ships its own hash) are left untouched.
        |
        */
        'skip_if_integrity_present' => true,

        /*
        |--------------------------------------------------------------------------
        | Host Allowlist
        |--------------------------------------------------------------------------
        |
        | Hosts whose <link>/<script> URLs are eligible for SRI pinning. SRI is
        | only meaningful for resources whose bytes you control or whose vendor
        | guarantees byte-stability for a versioned URL. Pinning third-party
        | mutable CDNs (reCAPTCHA, GTM, Maps, etc.) produces noise rather than
        | signal — those origins should be governed by CSP, not SRI.
        |
        | Special tokens:
        |   'self'  — the host of the current request (same-origin assets)
        |   'asset' — the host from config('app.asset_url') (the asset CDN)
        |
        | Anything else is treated as a literal hostname (exact match). To
        | pin a stable third-party (e.g. a versioned jsDelivr URL), add the
        | host explicitly here AND ensure the URL is in the manifest.
        |
        */
        'host_allowlist' => [
            'self',
            'asset',
        ],

        /*
        |--------------------------------------------------------------------------
        | Exclude Paths
        |--------------------------------------------------------------------------
        |
        | Request paths that should NOT have SRI injected. Typically admin
        | panels and Livewire endpoints.
        |
        */
        'exclude_paths' => ['admin', 'livewire'],

        /*
        |--------------------------------------------------------------------------
        | Skip URL Patterns
        |--------------------------------------------------------------------------
        |
        | Substring patterns matched against <link>/<script> URLs at injection
        | time. A match means the tag is left untouched — no integrity, no
        | crossorigin, and the observer doesn't report on it.
        |
        | Used for assets that exist in the manifest but whose served bytes
        | differ from the manifest hash for legitimate reasons (e.g. dynamic
        | route handlers that bake per-request config into the response).
        |
        | Default: '/livewire/' — Livewire serves its JS through a controller
        | that injects environment-aware config, so its bytes legitimately
        | drift across deploys/preview environments and shouldn't be pinned.
        |
        */
        'skip_url_patterns' => [
            '/livewire/',
        ],

        /*
        |--------------------------------------------------------------------------
        | Client-Side Failure Reporting
        |--------------------------------------------------------------------------
        |
        | Browsers don't send CSP reports for plain SRI hash mismatches, so the
        | package injects a small inline observer into <head> that listens for
        | error events on <script>/<link> elements carrying an integrity attr
        | and POSTs a JSON report to `path`. The registered route is outside
        | the `web` middleware group (no session, no CSRF) and rate-limited.
        |
        | Set `endpoint` to override the POST target (e.g. a third-party
        | reporting service); leaving it null uses the registered route.
        |
        */
        'report' => [
            'register_route' => env('SRI_REPORT_ROUTE', true),
            'path' => env('SRI_REPORT_PATH', '/sri-report'),
            'throttle' => env('SRI_REPORT_THROTTLE', '60,1'),
            'channel' => env('SRI_REPORT_CHANNEL', null),
            'inject_observer' => env('SRI_REPORT_OBSERVER', true),
            'endpoint' => env('SRI_REPORT_ENDPOINT', null),

            /*
            | Persist each report to the database in addition to the log
            | channel. The package ships a migration that creates the table
            | named below (auto-loaded; no publish required). Set
            | `connection` to route writes to a non-default DB.
            */
            'store_in_db' => env('SRI_REPORT_DB', true),
            'table' => env('SRI_REPORT_TABLE', 'sri_reports'),
            'connection' => env('SRI_REPORT_DB_CONNECTION', null),
        ],

    ],

];
