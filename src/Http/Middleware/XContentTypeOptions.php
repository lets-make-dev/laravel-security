<?php

namespace MakeDev\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class XContentTypeOptions
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! config('security.xcto.enabled')) {
            return $response;
        }

        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }
}
