<?php

namespace MakeDev\Security;

use MakeDev\Security\Console\Commands\SecurityInstall;
use MakeDev\Security\Console\Commands\SriBuildManifest;
use MakeDev\Security\Console\Commands\SriWarm;
use MakeDev\Security\Http\Controllers\CspReportController;
use MakeDev\Security\Http\Controllers\SriReportController;
use MakeDev\Security\Http\Middleware\ContentSecurityPolicy;
use MakeDev\Security\Http\Middleware\FrameOptions;
use MakeDev\Security\Http\Middleware\PermissionsPolicy;
use MakeDev\Security\Http\Middleware\StrictTransportSecurity;
use MakeDev\Security\Http\Middleware\SubresourceIntegrity;
use MakeDev\Security\Http\Middleware\XContentTypeOptions;
use MakeDev\Security\Services\CspNonce;
use MakeDev\Security\Services\SriManifest;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class SecurityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security.php', 'security');

        $this->app->singleton(SriManifest::class);
        $this->app->singleton(CspNonce::class);
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/security.php' => config_path('security.php'),
        ], 'make-dev-laravel-security');

        $this->registerCspReportRoute();
        $this->registerSriReportRoute();
        $this->registerBladeDirectives();

        if (config('security.sri.report.store_in_db', true)
            || config('security.csp.report.store_in_db', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityInstall::class,
                SriBuildManifest::class,
                SriWarm::class,
            ]);

            return;
        }

        $kernel = $this->app->make(\Illuminate\Contracts\Http\Kernel::class);

        // Header-only middlewares run globally so they cover 404s and other
        // unmatched-route responses, which never reach the web group.
        $kernel->pushMiddleware(StrictTransportSecurity::class);
        $kernel->pushMiddleware(ContentSecurityPolicy::class);
        $kernel->pushMiddleware(XContentTypeOptions::class);
        $kernel->pushMiddleware(PermissionsPolicy::class);
        $kernel->pushMiddleware(FrameOptions::class);

        // SRI rewrites HTML and only makes sense for matched web routes.
        $kernel->appendMiddlewareToGroup('web', SubresourceIntegrity::class);
    }

    protected function registerCspReportRoute(): void
    {
        if (! config('security.csp.report.register_route')) {
            return;
        }

        $path = ltrim((string) config('security.csp.report.path', '/csp-report'), '/');
        $throttle = config('security.csp.report.throttle', '60,1');

        Route::post($path, [CspReportController::class, 'store'])
            ->middleware("throttle:$throttle")
            ->name('make-dev.security.csp-report');
    }

    protected function registerSriReportRoute(): void
    {
        if (! config('security.sri.report.register_route')) {
            return;
        }

        $path = ltrim((string) config('security.sri.report.path', '/sri-report'), '/');
        $throttle = config('security.sri.report.throttle', '60,1');

        Route::post($path, [SriReportController::class, 'store'])
            ->middleware("throttle:$throttle")
            ->name('make-dev.security.sri-report');
    }

    /**
     * Register the @cspNonce Blade directive. Use as either the bare
     * attribute helper inside a tag — `<script @cspNonce>…</script>` —
     * or as the value side of a custom attribute via the csp_nonce()
     * helper: `<script nonce="{{ csp_nonce() }}">…</script>`.
     */
    protected function registerBladeDirectives(): void
    {
        Blade::directive('cspNonce', function () {
            return '<?php echo \'nonce="\' . e(app(\\MakeDev\\Security\\Services\\CspNonce::class)->value()) . \'"\'; ?>';
        });
    }
}
