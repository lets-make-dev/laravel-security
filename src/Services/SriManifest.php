<?php

namespace MakeDev\Security\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;

class SriManifest
{
    /** @var array<string, string|null>|null */
    protected ?array $manifest = null;

    protected string $algorithm;

    protected string $manifestPath;

    protected string $cachePrefix;

    protected ?string $cacheStore;

    public function __construct()
    {
        $this->algorithm = config('security.sri.algorithm', 'sha384');
        $this->manifestPath = config(
            'security.sri.manifest_path',
            base_path('bootstrap/cache/sri-manifest.json')
        );
        $this->cachePrefix = config('security.sri.cache_prefix', 'sri:');
        $this->cacheStore = config('security.sri.cache_store');
    }

    public function get(string $path): ?string
    {
        $path = $this->normalizePath($path);

        $overlay = $this->cache()->get($this->cachePrefix.$path);

        if (is_string($overlay) && $overlay !== '') {
            return $overlay;
        }

        return $this->load()[$path] ?? null;
    }

    public function put(string $path, string $hash): void
    {
        $this->cache()->forever($this->cachePrefix.$this->normalizePath($path), $hash);
    }

    /**
     * @return array<string, string|null>
     */
    public function load(): array
    {
        if ($this->manifest !== null) {
            return $this->manifest;
        }

        if (! is_file($this->manifestPath)) {
            return $this->manifest = [];
        }

        $decoded = json_decode((string) file_get_contents($this->manifestPath), true);

        return $this->manifest = is_array($decoded) ? $decoded : [];
    }

    /**
     * @param  array<string, string|null>  $manifest
     */
    public function write(array $manifest): void
    {
        ksort($manifest);

        file_put_contents(
            $this->manifestPath,
            json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n"
        );

        $this->manifest = $manifest;
    }

    public function hash(string $contents): string
    {
        return $this->algorithm.'-'.base64_encode(hash($this->algorithm, $contents, true));
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function manifestPath(): string
    {
        return $this->manifestPath;
    }

    protected function normalizePath(string $path): string
    {
        $path = parse_url($path, PHP_URL_PATH) ?? $path;
        $path = '/'.ltrim((string) $path, '/');

        $assetPath = rtrim((string) parse_url((string) config('app.asset_url'), PHP_URL_PATH), '/');

        if ($assetPath !== '' && $assetPath !== '/' && str_starts_with($path, $assetPath.'/')) {
            $path = substr($path, strlen($assetPath));
        }

        return $path;
    }

    protected function cache(): CacheRepository
    {
        return Cache::store($this->cacheStore);
    }
}
