<?php

namespace MakeDev\Security\Http\Middleware;

use MakeDev\Security\Services\CspNonce;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ContentSecurityPolicy
{
    public function __construct(protected CspNonce $nonce) {}

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! config('security.csp.enabled')) {
            return $response;
        }

        if ($this->shouldExclude($request)) {
            return $response;
        }

        $header = config('security.csp.report_only')
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        $response->headers->set($header, $this->buildPolicy());

        return $response;
    }

    protected function shouldExclude(Request $request): bool
    {
        $path = $request->path();

        foreach (config('security.csp.exclude_paths', []) as $excluded) {
            if (str_starts_with($path, $excluded)) {
                return true;
            }
        }

        return false;
    }

    protected function buildPolicy(): string
    {
        $directives = config('security.csp.directives', []);
        $assetDomains = $this->normalizeAssetDomains(config('security.csp.asset_domain'));

        $assetDirectives = ['script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'media-src'];

        $nonceEnabled = (bool) config('security.csp.nonce.enabled', false);
        $strictDynamic = (bool) config('security.csp.nonce.strict_dynamic', false);

        $parts = [];

        foreach ($directives as $directive => $sources) {
            $sources = array_values($sources);

            if ($assetDomains !== [] && in_array($directive, $assetDirectives)) {
                foreach ($assetDomains as $domain) {
                    $sources[] = $domain;
                }
            }

            if ($nonceEnabled && $directive === 'script-src') {
                // Nonce always emitted (rather than gated on $this->nonce->generated())
                // because 'strict-dynamic' requires a nonce or hash to be present in
                // the policy — without one, modern browsers ignore the origin
                // allowlist entirely and the page's external scripts get blocked.
                $sources[] = "'nonce-".$this->nonce->value()."'";

                if ($strictDynamic) {
                    $sources[] = "'strict-dynamic'";
                }
            }

            $parts[] = $directive . ' ' . implode(' ', $sources);
        }

        $reportUri = config('security.csp.report_uri')
            ?: (config('security.csp.report.register_route')
                ? config('security.csp.report.path')
                : null);

        if ($reportUri) {
            $parts[] = 'report-uri ' . $reportUri;
        }

        return implode('; ', $parts);
    }

    /**
     * @return array<int, string>
     */
    protected function normalizeAssetDomains(mixed $value): array
    {
        if (is_string($value)) {
            $value = str_contains($value, ',') ? explode(',', $value) : [$value];
        } elseif (! is_array($value)) {
            return [];
        }

        $domains = [];

        foreach ($value as $domain) {
            if (! is_string($domain)) {
                continue;
            }

            $domain = trim($domain);

            if ($domain !== '') {
                $domains[] = $domain;
            }
        }

        return array_values(array_unique($domains));
    }
}
