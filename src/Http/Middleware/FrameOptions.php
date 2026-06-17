<?php

namespace MakeDev\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class FrameOptions
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! config('security.frame_options.enabled')) {
            return $response;
        }

        $response->headers->set(
            'X-Frame-Options',
            config('security.frame_options.value', 'SAMEORIGIN')
        );

        return $response;
    }
}
