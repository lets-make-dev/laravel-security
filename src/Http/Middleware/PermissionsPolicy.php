<?php

namespace MakeDev\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class PermissionsPolicy
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! config('security.permissions_policy.enabled')) {
            return $response;
        }

        $directives = config('security.permissions_policy.directives', []);

        if (empty($directives)) {
            return $response;
        }

        $parts = [];
        foreach ($directives as $feature => $allowlist) {
            $parts[] = $feature.'=('.implode(' ', $allowlist).')';
        }

        $response->headers->set('Permissions-Policy', implode(', ', $parts));

        return $response;
    }
}
