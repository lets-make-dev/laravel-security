<?php

namespace MakeDev\Security\Http\Controllers;

use MakeDev\Security\Models\SriReport;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Throwable;

class SriReportController extends Controller
{
    public function store(Request $request): Response
    {
        $payload = json_decode($request->getContent(), true);

        if (! is_array($payload) || $payload === []) {
            return response()->noContent();
        }

        $reports = array_is_list($payload) ? $payload : [$payload];

        $channel = config('security.sri.report.channel') ?: config('logging.default');
        $storeInDb = (bool) config('security.sri.report.store_in_db', true);
        $allowedHosts = $this->allowedHosts($request);

        foreach ($reports as $report) {
            if (! is_array($report)) {
                continue;
            }

            $url = $this->string($report, 'url');

            if (! $this->isUrlAllowed($url, $allowedHosts)) {
                continue;
            }

            $record = [
                'url' => $url,
                'tag' => $this->string($report, 'tag'),
                'integrity' => $this->string($report, 'integrity'),
                'document_uri' => $this->string($report, 'documentUri'),
                'referrer' => $this->string($report, 'referrer') ?? $request->headers->get('referer'),
                'user_agent' => $request->userAgent(),
            ];

            Log::channel($channel)->warning('SRI failure', $record);

            if ($storeInDb) {
                $this->persist($record + ['ip' => $request->ip()]);
            }
        }

        return response()->noContent();
    }

    /**
     * @return array<int, string>
     */
    private function allowedHosts(Request $request): array
    {
        $configured = (array) config('security.sri.host_allowlist', []);
        $hosts = [];

        foreach ($configured as $entry) {
            if (! is_string($entry) || $entry === '') {
                continue;
            }

            if ($entry === 'self') {
                $hosts[] = strtolower((string) $request->getHost());

                continue;
            }

            if ($entry === 'asset') {
                $assetHost = parse_url((string) config('app.asset_url'), PHP_URL_HOST);

                if (is_string($assetHost) && $assetHost !== '') {
                    $hosts[] = strtolower($assetHost);
                }

                continue;
            }

            $hosts[] = strtolower($entry);
        }

        return array_values(array_unique(array_filter($hosts)));
    }

    /**
     * @param  array<int, string>  $allowedHosts
     */
    private function isUrlAllowed(?string $url, array $allowedHosts): bool
    {
        if ($url === null || $allowedHosts === []) {
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);

        if (! is_string($host) || $host === '') {
            return false;
        }

        return in_array(strtolower($host), $allowedHosts, true);
    }

    private function string(array $report, string $key): ?string
    {
        $value = $report[$key] ?? null;

        return is_string($value) && $value !== '' ? mb_substr($value, 0, 2048) : null;
    }

    private function persist(array $record): void
    {
        try {
            SriReport::create($record);
        } catch (Throwable $e) {
            Log::warning('Failed to persist SRI report', [
                'error' => $e->getMessage(),
            ]);
        }
    }
}
