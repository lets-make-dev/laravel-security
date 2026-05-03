<?php

namespace MakeDev\Security\Services;

class CspNonce
{
    private ?string $nonce = null;

    /**
     * Resolve (and lazily generate) the per-request nonce. Bound as a
     * singleton in the service provider so the same value is returned
     * for the lifetime of a request — both by the CSP middleware (when
     * building the script-src directive) and by Blade templates (via
     * the @cspNonce directive / csp_nonce() helper).
     */
    public function value(): string
    {
        return $this->nonce ??= rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
    }

    /**
     * Whether a nonce has actually been generated for this request.
     * Used by the middleware to decide if 'nonce-…' belongs in the
     * emitted policy at all (skipped when nothing on the page asked
     * for one, keeping the header lean for CDN/static responses).
     */
    public function generated(): bool
    {
        return $this->nonce !== null;
    }
}
