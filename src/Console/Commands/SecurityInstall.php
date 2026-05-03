<?php

namespace MakeDev\Security\Console\Commands;

use Illuminate\Console\Command;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\info;
use function Laravel\Prompts\multiselect;
use function Laravel\Prompts\note;
use function Laravel\Prompts\select;
use function Laravel\Prompts\text;
use function Laravel\Prompts\warning;

class SecurityInstall extends Command
{
    protected $signature = 'security:install
        {--force : Overwrite an existing config/security.php without prompting}';

    protected $description = 'Interactive setup wizard for make-dev/laravel-security.';

    /**
     * Curated CSP directive contributions for common third-party integrations.
     * Maintained as a starting point — verify against each vendor's current
     * documentation if a directive blocks a legitimate request.
     *
     * @var array<string, array{label: string, directives: array<string, list<string>>}>
     */
    private const INTEGRATIONS = [
        'gtm' => [
            'label' => 'Google Tag Manager / Google Analytics',
            'directives' => [
                'script-src' => [
                    'https://*.googletagmanager.com',
                    'https://www.google-analytics.com',
                ],
                'img-src' => [
                    'https://*.google-analytics.com',
                    'https://*.googletagmanager.com',
                ],
                'connect-src' => [
                    'https://*.google-analytics.com',
                    'https://*.analytics.google.com',
                    'https://*.googletagmanager.com',
                ],
            ],
        ],
        'gmaps' => [
            'label' => 'Google Maps (JS API / embeds)',
            'directives' => [
                'script-src' => ['https://maps.googleapis.com', 'https://maps.gstatic.com'],
                'img-src' => [
                    'https://maps.googleapis.com',
                    'https://maps.gstatic.com',
                    'https://*.googleapis.com',
                    'https://*.gstatic.com',
                ],
                'connect-src' => ['https://maps.googleapis.com'],
                'frame-src' => ['https://www.google.com'],
            ],
        ],
        'gfonts' => [
            'label' => 'Google Fonts',
            'directives' => [
                'style-src' => ['https://fonts.googleapis.com'],
                'font-src' => ['https://fonts.gstatic.com'],
            ],
        ],
        'bfonts' => [
            'label' => 'Bunny Fonts (privacy-friendly Google Fonts mirror)',
            'directives' => [
                'style-src' => ['https://fonts.bunny.net'],
                'font-src' => ['https://fonts.bunny.net'],
            ],
        ],
        'hubspot' => [
            'label' => 'HubSpot (forms, tracking, chat)',
            'directives' => [
                'script-src' => [
                    'https://js.hubspot.com',
                    'https://js.hsadspixel.net',
                    'https://js.hs-scripts.com',
                    'https://js.hsforms.net',
                    'https://js.hscollectedforms.net',
                    'https://js.hs-analytics.net',
                    'https://js.hs-banner.com',
                    'https://js.usemessages.com',
                    'https://*.hsappstatic.net',
                ],
                'connect-src' => [
                    'https://*.hubspot.com',
                    'https://api.hubapi.com',
                    'https://js.hs-banner.com',
                    'https://forms.hsforms.com',
                    'https://*.hsappstatic.net',
                ],
                'img-src' => ['https://track.hubspot.com', 'https://*.hsforms.com'],
                'frame-src' => ['https://forms.hsforms.com'],
            ],
        ],
        'linkedin' => [
            'label' => 'LinkedIn Insight Tag',
            'directives' => [
                'script-src' => ['https://snap.licdn.com'],
                'img-src' => ['https://px.ads.linkedin.com'],
                'connect-src' => ['https://px.ads.linkedin.com'],
            ],
        ],
        'meta' => [
            'label' => 'Meta / Facebook Pixel',
            'directives' => [
                'script-src' => ['https://connect.facebook.net'],
                'img-src' => ['https://www.facebook.com', 'https://*.facebook.com'],
                'connect-src' => ['https://www.facebook.com'],
            ],
        ],
        'youtube' => [
            'label' => 'YouTube embeds',
            'directives' => [
                'frame-src' => ['https://www.youtube.com', 'https://www.youtube-nocookie.com'],
                'script-src' => ['https://www.youtube.com'],
            ],
        ],
        'vimeo' => [
            'label' => 'Vimeo embeds',
            'directives' => [
                'frame-src' => ['https://player.vimeo.com'],
                'script-src' => ['https://player.vimeo.com'],
                'img-src' => ['https://i.vimeocdn.com'],
            ],
        ],
        'stripe' => [
            'label' => 'Stripe Elements / Checkout',
            'directives' => [
                'script-src' => ['https://js.stripe.com'],
                'frame-src' => ['https://js.stripe.com', 'https://hooks.stripe.com'],
                'connect-src' => ['https://api.stripe.com'],
            ],
        ],
        'recaptcha' => [
            'label' => 'Google reCAPTCHA',
            'directives' => [
                'script-src' => ['https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/'],
                'frame-src' => ['https://www.google.com/recaptcha/'],
            ],
        ],
        'turnstile' => [
            'label' => 'Cloudflare Turnstile',
            'directives' => [
                'script-src' => ['https://challenges.cloudflare.com'],
                'frame-src' => ['https://challenges.cloudflare.com'],
            ],
        ],
        'sentry' => [
            'label' => 'Sentry error reporting',
            'directives' => [
                'connect-src' => ['https://*.ingest.sentry.io', 'https://*.sentry.io'],
            ],
        ],
        'flare' => [
            'label' => 'Flare error reporting (Spatie)',
            'directives' => [
                'connect-src' => ['https://reporting.flareapp.io'],
            ],
        ],
        'bugsnag' => [
            'label' => 'Bugsnag error reporting',
            'directives' => [
                'connect-src' => ['https://notify.bugsnag.com', 'https://sessions.bugsnag.com'],
            ],
        ],
        'intercom' => [
            'label' => 'Intercom messenger',
            'directives' => [
                'script-src' => ['https://widget.intercom.io', 'https://js.intercomcdn.com'],
                'connect-src' => [
                    'https://api-iam.intercom.io',
                    'https://api-ping.intercom.io',
                    'https://nexus-websocket-a.intercom.io',
                    'wss://nexus-websocket-a.intercom.io',
                ],
                'img-src' => ['https://*.intercomcdn.com', 'https://js.intercomcdn.com'],
                'font-src' => ['https://js.intercomcdn.com'],
                'frame-src' => ['https://intercom-sheets.com'],
            ],
        ],
        'zoominfo' => [
            'label' => 'ZoomInfo / WebSights',
            'directives' => [
                'script-src' => ['https://js.zi-scripts.com'],
                'connect-src' => ['https://js.zi-scripts.com'],
            ],
        ],
    ];

    public function handle(): int
    {
        info('make-dev/laravel-security setup wizard');
        note(
            "This wizard generates a config/security.php tailored to your app.\n"
            ."Re-run any time. Existing config is backed up before overwrite."
        );

        $target = config_path('security.php');

        if (file_exists($target) && ! $this->option('force')) {
            $proceed = confirm(
                label: "config/security.php already exists. Back it up and overwrite?",
                default: false,
            );

            if (! $proceed) {
                warning('Aborted. No files written.');

                return self::SUCCESS;
            }
        }

        $config = [
            'hsts' => $this->configureHsts(),
            'csp' => $this->configureCsp(),
            'xcto' => $this->configureXcto(),
            'permissions_policy' => $this->configurePermissionsPolicy(),
            'sri' => $this->configureSri(),
        ];

        if (file_exists($target)) {
            $backup = $target.'.bak.'.date('Ymd-His');
            copy($target, $backup);
            info("Backed up existing config to {$backup}");
        }

        if (! is_dir(dirname($target))) {
            mkdir(dirname($target), 0755, true);
        }

        file_put_contents($target, $this->renderConfig($config));

        info("Wrote {$target}");

        $this->printNextSteps($config);

        return self::SUCCESS;
    }

    private function configureHsts(): array
    {
        $this->section('Strict-Transport-Security (HSTS)');

        note(
            "What: Forces the browser to use HTTPS for this domain for max-age seconds.\n"
            ."Pro:  Defeats SSL-stripping / protocol-downgrade attacks. After the first\n"
            ."      HTTPS visit, the browser refuses to even attempt plain HTTP.\n"
            ."Con:  Hard to undo. Once a browser caches the rule (or worse, the domain\n"
            ."      is on the preload list), HTTP fallback is impossible until max-age\n"
            ."      expires. Don't enable preload until every subdomain serves HTTPS."
        );

        $enabled = confirm('Enable HSTS?', default: true);

        if (! $enabled) {
            return ['enabled' => false, 'max_age' => 31536000, 'include_sub_domains' => true, 'preload' => false];
        }

        $maxAge = (int) text(
            label: 'max-age (seconds)',
            placeholder: '31536000',
            default: '31536000',
            hint: 'Default is 1 year. Use a low value (e.g. 300) while testing.',
            validate: fn (string $v) => ctype_digit($v) && (int) $v >= 0 ? null : 'Must be a non-negative integer.',
        );

        return [
            'enabled' => true,
            'max_age' => $maxAge,
            'include_sub_domains' => confirm('Include subdomains?', default: true),
            'preload' => confirm(
                label: 'Add the preload flag?',
                default: false,
                hint: 'Only enable once you submit the domain to hstspreload.org.',
            ),
        ];
    }

    private function configureCsp(): array
    {
        $this->section('Content-Security-Policy (CSP)');

        note(
            "What: A browser-enforced allowlist of where scripts, styles, images, fonts,\n"
            ."      and network calls may originate from.\n"
            ."Pro:  Strongest XSS mitigation available. A compromised dependency or\n"
            ."      stored-XSS payload can't exfiltrate data to an attacker host that\n"
            ."      isn't in the allowlist.\n"
            ."Con:  A strict policy will break analytics/marketing tags until each\n"
            ."      origin is explicitly listed. Roll out in report-only mode first."
        );

        $enabled = confirm('Enable CSP?', default: true);

        if (! $enabled) {
            return [
                'enabled' => false,
                'report_only' => true,
                'report_uri' => null,
                'asset_domain' => null,
                'exclude_paths' => [],
                'nonce' => ['enabled' => false, 'strict_dynamic' => false, 'auto_inject' => false],
                'directives' => $this->baseCspDirectives(),
                'report' => $this->defaultCspReport(),
            ];
        }

        $reportOnly = confirm(
            label: 'Start in report-only mode?',
            default: true,
            hint: 'Strongly recommended — collect violations for a few days, then enforce.',
        );

        $directives = $this->baseCspDirectives();

        note(
            "For inline scripts, the modern best practice is per-request\n"
            ."nonces + 'strict-dynamic' (Google's Strict CSP). The middleware\n"
            ."generates a nonce each request; mark trusted inline tags with\n"
            ."the @cspNonce Blade directive. With 'strict-dynamic', any\n"
            ."script loaded by a nonced script is also trusted, so vendor\n"
            ."tag allowlists become old-browser fallback rather than the\n"
            ."primary trust mechanism."
        );

        $useNonce = confirm(
            label: 'Enable per-request nonce for script-src?',
            default: true,
            hint: 'Recommended. Required to use the @cspNonce directive.',
        );

        $strictDynamic = $useNonce && confirm(
            label: "Also enable 'strict-dynamic'?",
            default: true,
            hint: "Lets nonced scripts load further scripts. Origin allowlist becomes fallback for old browsers.",
        );

        $allowUnsafeInline = confirm(
            label: "Fall back to 'unsafe-inline' scripts?",
            default: false,
            hint: 'Inline <script> tags without a nonce. Defeats most XSS protection; only enable for legacy code.',
        );

        $allowUnsafeEval = confirm(
            label: "Allow 'unsafe-eval' scripts?",
            default: false,
            hint: 'eval()/Function(). Required by some legacy frameworks; weakens CSP.',
        );

        if ($allowUnsafeInline) {
            $directives['script-src'][] = "'unsafe-inline'";
        }

        if ($allowUnsafeEval) {
            $directives['script-src'][] = "'unsafe-eval'";
        }

        note(
            "Pick the third-party integrations your app actually uses.\n"
            ."Each preset adds the vendor's documented origins to the right directives.\n"
            ."You can edit the generated config afterwards to refine."
        );

        $integrationLabels = [];
        foreach (self::INTEGRATIONS as $key => $integration) {
            $integrationLabels[$key] = $integration['label'];
        }

        $selected = multiselect(
            label: 'Which integrations do you use?',
            options: $integrationLabels,
            scroll: 12,
            hint: 'Space to select, Enter to confirm. None is also fine.',
        );

        foreach ($selected as $key) {
            foreach (self::INTEGRATIONS[$key]['directives'] as $directive => $sources) {
                $directives[$directive] = array_values(array_unique(
                    array_merge($directives[$directive] ?? [], $sources)
                ));
            }
        }

        $assetDomainRaw = text(
            label: 'CDN / asset host(s) (optional)',
            placeholder: 'https://cdn.example.com, https://bucket.s3.amazonaws.com',
            hint: 'Comma-separated for multiple hosts. Each one is auto-appended to script-src, style-src, img-src, font-src, connect-src, media-src. Leave blank if you serve assets from your own origin.',
        );
        $assetDomainList = array_values(array_filter(array_map('trim', explode(',', $assetDomainRaw))));
        $assetDomain = match (count($assetDomainList)) {
            0 => null,
            1 => $assetDomainList[0],
            default => $assetDomainList,
        };

        $extraOriginsRaw = text(
            label: 'Other origins to allow (comma-separated, optional)',
            placeholder: 'https://example.com, https://*.example.org',
            hint: "Added to connect-src + img-src. Use only if you need a custom S3 bucket, your own CDN, etc.",
        );

        $extraOrigins = array_values(array_filter(array_map('trim', explode(',', $extraOriginsRaw))));

        if ($extraOrigins !== []) {
            $directives['connect-src'] = array_values(array_unique(array_merge($directives['connect-src'], $extraOrigins)));
            $directives['img-src'] = array_values(array_unique(array_merge($directives['img-src'], $extraOrigins)));
        }

        $excludeRaw = text(
            label: 'Paths to exclude from CSP (comma-separated)',
            placeholder: 'admin, livewire',
            default: 'admin, livewire',
            hint: 'Useful for admin panels / Livewire endpoints that manage their own asset graph.',
        );

        $excludePaths = array_values(array_filter(array_map('trim', explode(',', $excludeRaw))));

        return [
            'enabled' => true,
            'report_only' => $reportOnly,
            'report_uri' => null,
            'report' => $this->configureCspReport(),
            'asset_domain' => $assetDomain,
            'exclude_paths' => $excludePaths,
            'nonce' => [
                'enabled' => $useNonce,
                'strict_dynamic' => $strictDynamic,
                'auto_inject' => $useNonce,
            ],
            'directives' => $directives,
        ];
    }

    private function configureCspReport(): array
    {
        note(
            "CSP can be configured to POST violation reports back to your app.\n"
            ."The package can register that endpoint, write each report to the log\n"
            ."channel, and persist them to a database table for triage."
        );

        $register = confirm('Register the built-in /csp-report route?', default: true);
        $storeInDb = $register
            ? confirm('Persist reports to the csp_reports table?', default: true)
            : false;

        return [
            'register_route' => $register,
            'path' => '/csp-report',
            'throttle' => '60,1',
            'channel' => null,
            'store_in_db' => $storeInDb,
            'table' => 'csp_reports',
            'connection' => null,
        ];
    }

    private function configureXcto(): array
    {
        $this->section('X-Content-Type-Options');

        note(
            "What: Tells browsers not to MIME-sniff. A file served as text/plain stays\n"
            ."      text/plain even if the bytes look like HTML or JavaScript.\n"
            ."Pro:  Cheap. Blocks a class of upload-and-execute exploits where a\n"
            ."      malicious .jpg gets sniffed as HTML.\n"
            ."Con:  Effectively none. Always enable."
        );

        return [
            'enabled' => confirm('Enable X-Content-Type-Options: nosniff?', default: true),
        ];
    }

    private function configurePermissionsPolicy(): array
    {
        $this->section('Permissions-Policy');

        note(
            "What: Disables specific browser APIs (camera, mic, geolocation, payment,\n"
            ."      USB) for your origin and any iframes you embed.\n"
            ."Pro:  Compromised JS can't silently prompt the user for the camera or\n"
            ."      grab geolocation if the policy denies those features.\n"
            ."Con:  If your app legitimately uses one of these APIs, you must opt the\n"
            ."      relevant page in (set the feature to 'self' instead of denied)."
        );

        $enabled = confirm('Enable Permissions-Policy?', default: true);

        $features = ['accelerometer', 'camera', 'geolocation', 'gyroscope', 'magnetometer', 'microphone', 'payment', 'usb'];

        $allowed = $enabled
            ? multiselect(
                label: 'Which features does your app legitimately use?',
                options: array_combine($features, $features),
                hint: 'Selected features will be allowed for same-origin (\'self\'). Unselected = denied.',
            )
            : [];

        $directives = [];
        foreach ($features as $feature) {
            $directives[$feature] = in_array($feature, $allowed, true) ? ["'self'"] : [];
        }

        return [
            'enabled' => $enabled,
            'directives' => $directives,
        ];
    }

    private function configureSri(): array
    {
        $this->section('Subresource Integrity (SRI)');

        note(
            "What: Adds an integrity= hash to <script> and <link> tags so browsers\n"
            ."      refuse to execute the resource if its bytes don't match.\n"
            ."Pro:  Catches CDN compromise, MITM tampering, and accidental asset drift.\n"
            ."Con:  Adds a deploy step (sri:build-manifest after asset build). Only\n"
            ."      hashable for stable assets — third-party scripts whose contents\n"
            ."      change at the source (e.g. raw GTM) can't be hashed."
        );

        $enabled = confirm('Enable SRI rewriting?', default: true);

        if (! $enabled) {
            return [
                'enabled' => false,
                'algorithm' => 'sha384',
                'manifest_path' => null,
                'scan_dirs' => ['build', 'css', 'js'],
                'warm_from_app' => [],
                'cache_store' => null,
                'cache_prefix' => 'sri:',
                'skip_if_integrity_present' => true,
                'host_allowlist' => ['self', 'asset'],
                'exclude_paths' => ['admin', 'livewire'],
                'skip_url_patterns' => ['/livewire/'],
                'report' => $this->defaultSriReport(false),
            ];
        }

        $injectObserver = confirm(
            label: 'Inject the client-side failure observer?',
            default: true,
            hint: 'Tiny inline script that POSTs SRI failures (browsers do not send CSP reports for SRI mismatches).',
        );

        $registerRoute = $injectObserver && confirm(
            label: 'Register the built-in /sri-report route?',
            default: true,
        );

        $storeInDb = $registerRoute
            ? confirm('Persist SRI reports to the sri_reports table?', default: true)
            : false;

        $excludeRaw = text(
            label: 'Paths to exclude from SRI rewriting (comma-separated)',
            default: 'admin, livewire',
            hint: 'Pages that manage their own asset graph (e.g. Livewire endpoints).',
        );
        $excludePaths = array_values(array_filter(array_map('trim', explode(',', $excludeRaw))));

        return [
            'enabled' => true,
            'algorithm' => 'sha384',
            'manifest_path' => null,
            'scan_dirs' => ['build', 'css', 'js'],
            'warm_from_app' => [],
            'cache_store' => null,
            'cache_prefix' => 'sri:',
            'skip_if_integrity_present' => true,
            'host_allowlist' => ['self', 'asset'],
            'exclude_paths' => $excludePaths,
            'skip_url_patterns' => ['/livewire/'],
            'report' => [
                'register_route' => $registerRoute,
                'path' => '/sri-report',
                'throttle' => '60,1',
                'channel' => null,
                'inject_observer' => $injectObserver,
                'endpoint' => null,
                'store_in_db' => $storeInDb,
                'table' => 'sri_reports',
                'connection' => null,
            ],
        ];
    }

    private function baseCspDirectives(): array
    {
        return [
            'default-src' => ["'self'"],
            'script-src' => ["'self'"],
            // Inline style attributes are pervasive in CMS-rendered content
            // and framework output (Filament, TinyMCE, page builders). They
            // can't exfiltrate data, so 'unsafe-inline' is OWASP-acceptable
            // and avoids a flood of style-src-attr violations.
            'style-src' => ["'self'", "'unsafe-inline'"],
            'style-src-attr' => ["'self'", "'unsafe-inline'"],
            'img-src' => ["'self'", 'data:'],
            'font-src' => ["'self'", 'data:'],
            'connect-src' => ["'self'"],
            'media-src' => ["'self'"],
            'frame-src' => ["'self'"],
            'object-src' => ["'none'"],
            'base-uri' => ["'self'"],
        ];
    }

    private function defaultCspReport(): array
    {
        return [
            'register_route' => true,
            'path' => '/csp-report',
            'throttle' => '60,1',
            'channel' => null,
            'store_in_db' => true,
            'table' => 'csp_reports',
            'connection' => null,
        ];
    }

    private function defaultSriReport(bool $injectObserver): array
    {
        return [
            'register_route' => $injectObserver,
            'path' => '/sri-report',
            'throttle' => '60,1',
            'channel' => null,
            'inject_observer' => $injectObserver,
            'endpoint' => null,
            'store_in_db' => $injectObserver,
            'table' => 'sri_reports',
            'connection' => null,
        ];
    }

    private function section(string $title): void
    {
        $this->newLine();
        $this->line('<fg=cyan;options=bold>'.$title.'</>');
        $this->line('<fg=cyan>'.str_repeat('─', mb_strlen($title)).'</>');
    }

    /**
     * Render the chosen config to a clean, readable PHP file.
     * Each top-level section is rendered with a brief comment header so the
     * output reads like a hand-written config rather than a var_export blob.
     */
    private function renderConfig(array $config): string
    {
        $hsts = $this->renderArray($config['hsts'], 1);
        $csp = $this->renderCsp($config['csp']);
        $xcto = $this->renderArray($config['xcto'], 1);
        $perms = $this->renderArray($config['permissions_policy'], 1);
        $sri = $this->renderSri($config['sri']);

        return <<<PHP
        <?php

        /*
         * Generated by `php artisan security:install`.
         * Re-run the wizard at any time, or hand-edit this file.
         */

        return [

            // Strict-Transport-Security: forces HTTPS at the browser layer.
            'hsts' => {$hsts},

            // Content-Security-Policy: source allowlist for scripts, styles, images, etc.
            'csp' => {$csp},

            // X-Content-Type-Options: nosniff. Disables MIME-sniffing.
            'xcto' => {$xcto},

            // Permissions-Policy: per-feature browser API allowlist.
            'permissions_policy' => {$perms},

            // Subresource Integrity: hashes assets and rewrites tags with integrity=.
            'sri' => {$sri},

        ];

        PHP;
    }

    private function renderCsp(array $csp): string
    {
        $report = $this->renderArray($csp['report'], 2);
        $directives = $this->renderArray($csp['directives'], 2);
        $excludePaths = $this->renderArray($csp['exclude_paths'], 2);

        $assetDomain = match (true) {
            $csp['asset_domain'] === null => 'null',
            is_array($csp['asset_domain']) => $this->renderArray($csp['asset_domain'], 2),
            default => var_export($csp['asset_domain'], true),
        };

        $enabledExpr = $csp['enabled'] ? "env('CSP_ENABLED', true)" : 'false';
        $reportOnlyExpr = "env('CSP_REPORT_ONLY', ".($csp['report_only'] ? 'true' : 'false').')';
        $assetDomainExpr = "env('CSP_ASSET_DOMAIN', {$assetDomain})";
        $reportUriExpr = "env('CSP_REPORT_URI', null)";

        $nonceEnabledExpr = "env('CSP_NONCE', ".($csp['nonce']['enabled'] ? 'true' : 'false').')';
        $strictDynamicExpr = "env('CSP_STRICT_DYNAMIC', ".($csp['nonce']['strict_dynamic'] ? 'true' : 'false').')';
        $autoInjectExpr = "env('CSP_NONCE_AUTO_INJECT', ".($csp['nonce']['auto_inject'] ? 'true' : 'false').')';

        return <<<PHP
        [
                'enabled' => {$enabledExpr},
                'report_only' => {$reportOnlyExpr},
                'report_uri' => {$reportUriExpr},
                'asset_domain' => {$assetDomainExpr},
                'exclude_paths' => {$excludePaths},
                'nonce' => [
                    'enabled' => {$nonceEnabledExpr},
                    'strict_dynamic' => {$strictDynamicExpr},
                    'auto_inject' => {$autoInjectExpr},
                ],
                'report' => {$report},
                'directives' => {$directives},
            ]
        PHP;
    }

    private function renderSri(array $sri): string
    {
        $report = $this->renderArray($sri['report'], 2);
        $scanDirs = $this->renderArray($sri['scan_dirs'], 2);
        $warmFromApp = $this->renderArray($sri['warm_from_app'], 2);
        $hostAllowlist = $this->renderArray($sri['host_allowlist'], 2);
        $excludePaths = $this->renderArray($sri['exclude_paths'], 2);
        $skipUrlPatterns = $this->renderArray($sri['skip_url_patterns'], 2);

        $enabledExpr = "env('SRI_ENABLED', ".($sri['enabled'] ? 'true' : 'false').')';
        $manifestExpr = "base_path('bootstrap/cache/sri-manifest.json')";
        $cacheStoreExpr = "env('SRI_CACHE_STORE', null)";

        $algorithm = var_export($sri['algorithm'], true);
        $cachePrefix = var_export($sri['cache_prefix'], true);
        $skipIfPresent = $sri['skip_if_integrity_present'] ? 'true' : 'false';

        return <<<PHP
        [
                'enabled' => {$enabledExpr},
                'algorithm' => {$algorithm},
                'manifest_path' => {$manifestExpr},
                'scan_dirs' => {$scanDirs},
                'warm_from_app' => {$warmFromApp},
                'cache_store' => {$cacheStoreExpr},
                'cache_prefix' => {$cachePrefix},
                'skip_if_integrity_present' => {$skipIfPresent},
                'host_allowlist' => {$hostAllowlist},
                'exclude_paths' => {$excludePaths},
                'skip_url_patterns' => {$skipUrlPatterns},
                'report' => {$report},
            ]
        PHP;
    }

    private function renderArray(array $arr, int $indent): string
    {
        if ($arr === []) {
            return '[]';
        }

        $isList = array_is_list($arr);
        $pad = str_repeat('    ', $indent);
        $childPad = str_repeat('    ', $indent + 1);

        $lines = [];
        foreach ($arr as $key => $value) {
            $line = $childPad;

            if (! $isList) {
                $line .= var_export($key, true).' => ';
            }

            if (is_array($value)) {
                $line .= $this->renderArray($value, $indent + 1);
            } elseif (is_string($value)) {
                $line .= var_export($value, true);
            } elseif (is_bool($value)) {
                $line .= $value ? 'true' : 'false';
            } elseif ($value === null) {
                $line .= 'null';
            } else {
                $line .= var_export($value, true);
            }

            $lines[] = $line.',';
        }

        return "[\n".implode("\n", $lines)."\n".$pad.']';
    }

    private function printNextSteps(array $config): void
    {
        $this->newLine();
        $this->section('Next steps');

        $steps = ['Review the generated config/security.php and tune to taste.'];

        $needsMigrate = ($config['csp']['report']['store_in_db'] ?? false)
            || ($config['sri']['report']['store_in_db'] ?? false);

        if ($needsMigrate) {
            $steps[] = 'Run `php artisan migrate` to create the csp_reports / sri_reports tables.';
        }

        if ($config['sri']['enabled'] ?? false) {
            $steps[] = 'Add `php artisan sri:build-manifest` to your deploy build (after `vite build`).';
        }

        if (($config['csp']['enabled'] ?? false) && ($config['csp']['report_only'] ?? false)) {
            $steps[] = 'Tail your log channel for a few days to surface broken integrations, then set CSP_REPORT_ONLY=false to enforce.';
        }

        if (($config['hsts']['enabled'] ?? false) && ($config['hsts']['preload'] ?? false)) {
            $steps[] = 'Submit your domain at https://hstspreload.org/ to land on the browser preload list.';
        }

        foreach ($steps as $i => $step) {
            $this->line(sprintf('  <fg=green>%d.</> %s', $i + 1, $step));
        }

        $this->newLine();
    }
}
