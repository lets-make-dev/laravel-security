<?php

namespace MakeDev\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class StrictTransportSecurity
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! config('security.hsts.enabled')) {
            return $response;
        }

        $value = 'max-age='.config('security.hsts.max_age');

        if (config('security.hsts.include_sub_domains')) {
            $value .= '; includeSubDomains';
        }

        if (config('security.hsts.preload')) {
            $value .= '; preload';
        }

        $response->headers->set('Strict-Transport-Security', $value);

        return $response;
    }
}
