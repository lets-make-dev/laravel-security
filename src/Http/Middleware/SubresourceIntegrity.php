<?php

namespace MakeDev\Security\Http\Middleware;

use MakeDev\Security\Services\CspNonce;
use MakeDev\Security\Services\SriManifest;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

class SubresourceIntegrity
{
    /** @var array<int, string>|null */
    protected ?array $resolvedAllowlist = null;

    protected ?string $requestHost = null;

    public function __construct(protected SriManifest $manifest, protected CspNonce $nonce) {}

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! config('security.sri.enabled')) {
            return $response;
        }

        if ($this->shouldExclude($request)) {
            return $response;
        }

        if ($response instanceof StreamedResponse || $response instanceof BinaryFileResponse) {
            return $response;
        }

        if (! $this->isHtmlResponse($response)) {
            return $response;
        }

        $content = $response->getContent();

        if (! is_string($content) || $content === '') {
            return $response;
        }

        $this->requestHost = strtolower((string) $request->getHost());
        $this->resolvedAllowlist = $this->resolveAllowlist($this->requestHost);

        $modified = $this->injectIntegrity($content);
        $modified = $this->injectNonces($modified);
        $modified = $this->injectObserver($modified);

        if ($modified !== $content) {
            $response->setContent($modified);
        }

        return $response;
    }

    protected function shouldExclude(Request $request): bool
    {
        $path = $request->path();

        foreach ((array) config('security.sri.exclude_paths', []) as $excluded) {
            if (str_starts_with($path, $excluded)) {
                return true;
            }
        }

        return false;
    }

    protected function isHtmlResponse(Response $response): bool
    {
        return str_contains((string) $response->headers->get('Content-Type', ''), 'text/html');
    }

    protected function injectIntegrity(string $content): string
    {
        $content = preg_replace_callback(
            '/<link\b([^>]*?)\s*\/?>/i',
            fn (array $match) => $this->processTag($match[0], $match[1], 'href'),
            $content
        ) ?? $content;

        $content = preg_replace_callback(
            '/<script\b([^>]*?)>/i',
            fn (array $match) => $this->processTag($match[0], $match[1], 'src'),
            $content
        ) ?? $content;

        return $content;
    }

    protected function processTag(string $fullTag, string $attributes, string $urlAttr): string
    {
        if (config('security.sri.skip_if_integrity_present', true)
            && preg_match('/\bintegrity\s*=/i', $attributes)) {
            return $fullTag;
        }

        if (! preg_match('/\b'.$urlAttr.'\s*=\s*["\']([^"\']+)["\']/i', $attributes, $urlMatch)) {
            return $fullTag;
        }

        $url = $urlMatch[1];

        if ($this->matchesSkipPattern($url)) {
            return $fullTag;
        }

        if (! $this->isHostAllowed($url)) {
            return $fullTag;
        }

        $hash = $this->manifest->get($url);

        if ($hash === null) {
            return $fullTag;
        }

        $injection = ' integrity="'.$hash.'" data-sri-managed=""';

        if ($this->isCrossOrigin($url)) {
            $injection .= ' crossorigin="anonymous"';
        }

        if (str_ends_with($fullTag, '/>')) {
            return substr($fullTag, 0, -2).$injection.'/>';
        }

        return substr($fullTag, 0, -1).$injection.'>';
    }

    /**
     * Inject the per-request CSP nonce on every <script> tag that doesn't
     * already carry one. Catches CMS-rendered raw HTML (Filament Fabricator
     * `html` / `content` / etc. blocks emit admin-authored markup via
     * {!! … !!}, which can't be statically annotated with @cspNonce).
     *
     * Trust model: the server-rendered response is treated as trusted by
     * design — a nonce attached here is no more permissive than the same
     * markup with @cspNonce in a hand-written Blade template. Sites that
     * render *user-generated* HTML through {!! !!} should set
     * security.csp.nonce.auto_inject = false and gate trust per-template.
     */
    protected function injectNonces(string $content): string
    {
        if (! config('security.csp.nonce.enabled')) {
            return $content;
        }

        if (! config('security.csp.nonce.auto_inject', true)) {
            return $content;
        }

        $nonce = htmlspecialchars($this->nonce->value(), ENT_QUOTES, 'UTF-8');

        return preg_replace_callback(
            '/<script\b([^>]*)>/i',
            function (array $match) use ($nonce) {
                if (preg_match('/\bnonce\s*=/i', $match[1])) {
                    return $match[0];
                }

                return '<script'.$match[1].' nonce="'.$nonce.'">';
            },
            $content
        ) ?? $content;
    }

    protected function matchesSkipPattern(string $url): bool
    {
        foreach ((array) config('security.sri.skip_url_patterns', []) as $pattern) {
            if (! is_string($pattern) || $pattern === '') {
                continue;
            }

            if (str_contains($url, $pattern)) {
                return true;
            }
        }

        return false;
    }

    protected function isHostAllowed(string $url): bool
    {
        $allowlist = $this->resolvedAllowlist ?? [];

        if ($allowlist === []) {
            return false;
        }

        $host = $this->urlHost($url);

        if ($host === null) {
            // Relative URL — same-origin by definition.
            return in_array($this->requestHost ?? '', $allowlist, true);
        }

        return in_array(strtolower($host), $allowlist, true);
    }

    protected function isCrossOrigin(string $url): bool
    {
        $host = $this->urlHost($url);

        if ($host === null) {
            return false;
        }

        return strtolower($host) !== ($this->requestHost ?? '');
    }

    protected function urlHost(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : null;
    }

    /**
     * @return array<int, string>
     */
    protected function resolveAllowlist(string $requestHost): array
    {
        $configured = (array) config('security.sri.host_allowlist', []);
        $hosts = [];

        foreach ($configured as $entry) {
            if (! is_string($entry) || $entry === '') {
                continue;
            }

            if ($entry === 'self') {
                if ($requestHost !== '') {
                    $hosts[] = $requestHost;
                }

                continue;
            }

            if ($entry === 'asset') {
                foreach ($this->assetHosts() as $assetHost) {
                    $hosts[] = $assetHost;
                }

                continue;
            }

            $hosts[] = strtolower($entry);
        }

        return array_values(array_unique($hosts));
    }

    /**
     * Resolve hosts from configured asset domains. Accepts the legacy single
     * string in app.asset_url plus the (possibly multi-valued) CSP asset_domain
     * setting, since SRI eligibility usually mirrors what CSP allows from a CDN.
     *
     * @return array<int, string>
     */
    protected function assetHosts(): array
    {
        $candidates = [(string) config('app.asset_url')];

        $cspAssetDomain = config('security.csp.asset_domain');

        if (is_string($cspAssetDomain)) {
            $candidates = array_merge(
                $candidates,
                str_contains($cspAssetDomain, ',') ? explode(',', $cspAssetDomain) : [$cspAssetDomain]
            );
        } elseif (is_array($cspAssetDomain)) {
            foreach ($cspAssetDomain as $entry) {
                if (is_string($entry)) {
                    $candidates[] = $entry;
                }
            }
        }

        $hosts = [];

        foreach ($candidates as $candidate) {
            $candidate = trim((string) $candidate);

            if ($candidate === '') {
                continue;
            }

            $host = parse_url($candidate, PHP_URL_HOST);

            if (is_string($host) && $host !== '') {
                $hosts[] = strtolower($host);
            }
        }

        return array_values(array_unique($hosts));
    }

    protected function injectObserver(string $content): string
    {
        $endpoint = $this->reportEndpoint();

        if ($endpoint === null) {
            return $content;
        }

        $endpointJson = json_encode($endpoint, JSON_UNESCAPED_SLASHES);
        $nonceAttr = config('security.csp.nonce.enabled')
            ? ' nonce="'.htmlspecialchars($this->nonce->value(), ENT_QUOTES, 'UTF-8').'"'
            : '';
        $script = '<script'.$nonceAttr.'>!function(){var e='.$endpointJson.';function n(n){try{var t={url:n.src||n.href||null,tag:n.tagName,integrity:n.getAttribute("integrity"),documentUri:location.href,referrer:document.referrer||null},r=JSON.stringify(t);navigator.sendBeacon?navigator.sendBeacon(e,new Blob([r],{type:"application/json"})):fetch(e,{method:"POST",body:r,headers:{"Content-Type":"application/json"},keepalive:!0,credentials:"same-origin"})}catch(e){}}window.addEventListener("error",function(e){var t=e.target;t&&t.getAttribute&&t.hasAttribute("data-sri-managed")&&("SCRIPT"===t.tagName||"LINK"===t.tagName)&&n(t)},!0)}();</script>';

        $replaced = preg_replace('/<head\b[^>]*>/i', '$0'.$script, $content, 1);

        return $replaced ?? $content;
    }

    protected function reportEndpoint(): ?string
    {
        if (! config('security.sri.report.inject_observer', true)) {
            return null;
        }

        $explicit = config('security.sri.report.endpoint');

        if (is_string($explicit) && $explicit !== '') {
            return $explicit;
        }

        if (! config('security.sri.report.register_route', true)) {
            return null;
        }

        return '/'.ltrim((string) config('security.sri.report.path', '/sri-report'), '/');
    }
}
