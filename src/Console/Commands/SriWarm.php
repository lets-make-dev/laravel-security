<?php

namespace MakeDev\Security\Console\Commands;

use MakeDev\Security\Services\SriManifest;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

class SriWarm extends Command
{
    protected $signature = 'sri:warm
        {--force : Warm hashes even for entries that are already populated}';

    protected $description = 'Fetch assets over HTTP, hash them, and populate the SRI cache overlay.';

    public function handle(SriManifest $sri): int
    {
        $assetUrl = rtrim((string) config('app.asset_url'), '/');
        $appUrl = rtrim((string) config('app.url'), '/');

        if ($assetUrl === '' && $appUrl === '') {
            $this->error('Neither app.asset_url nor app.url is set; cannot fetch assets.');

            return self::FAILURE;
        }

        $appHostPaths = array_map(
            fn ($p) => '/'.ltrim((string) $p, '/'),
            (array) config('security.sri.warm_from_app', [])
        );

        $manifest = $sri->load();

        $targets = [];
        foreach ($manifest as $path => $hash) {
            if ($hash !== null && ! $this->option('force')) {
                continue;
            }

            $targets[] = $path;
        }

        if ($targets === []) {
            $this->info('No manifest entries need warming.');

            return self::SUCCESS;
        }

        $warmed = 0;
        $failed = 0;

        foreach ($targets as $path) {
            $base = in_array($path, $appHostPaths, true)
                ? ($appUrl !== '' ? $appUrl : $assetUrl)
                : ($assetUrl !== '' ? $assetUrl : $appUrl);

            if ($base === '') {
                $this->warn("Skipping {$path}: no base URL configured for this source.");
                $failed++;

                continue;
            }

            $url = $base.$path;

            try {
                $response = Http::timeout(10)->get($url);
            } catch (\Throwable $e) {
                $this->warn("Error fetching {$url}: {$e->getMessage()}");
                $failed++;

                continue;
            }

            if (! $response->successful()) {
                $this->warn("Failed to fetch {$url}: HTTP {$response->status()}");
                $failed++;

                continue;
            }

            $sri->put($path, $sri->hash($response->body()));
            $warmed++;
        }

        $this->info(sprintf('Warmed SRI cache for %d assets (%d failed).', $warmed, $failed));

        // Per-asset fetch failures don't fail the deploy — assets without hashes
        // just get no integrity attribute. Only bail if nothing warmed at all.
        return $warmed === 0 && $failed > 0 ? self::FAILURE : self::SUCCESS;
    }
}
