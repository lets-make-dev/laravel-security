<?php

namespace MakeDev\Security\Console\Commands;

use MakeDev\Security\Services\SriManifest;
use Illuminate\Console\Command;
use Symfony\Component\Finder\Finder;

class SriBuildManifest extends Command
{
    protected $signature = 'sri:build-manifest
        {--skip-css : Leave CSS entries in the manifest with null hashes for later warming (use on Vapor builds)}';

    protected $description = 'Scan public asset directories and write an SRI manifest of content hashes.';

    public function handle(SriManifest $sri): int
    {
        $skipCss = (bool) $this->option('skip-css');

        $scanDirs = config('security.sri.scan_dirs', ['build', 'css', 'js']);

        $extensions = ['js', 'css'];

        $existingDirs = [];
        foreach ($scanDirs as $relative) {
            $absolute = public_path($relative);
            if (is_dir($absolute)) {
                $existingDirs[] = $absolute;
            }
        }

        if ($existingDirs === []) {
            $this->warn('No scan directories exist under public/. Nothing to hash.');

            return self::SUCCESS;
        }

        $finder = Finder::create()
            ->files()
            ->in($existingDirs)
            ->name('*.js')
            ->name('*.css')
            ->notName('*.map');

        $manifest = [];
        $publicPath = rtrim(public_path(), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

        foreach ($finder as $file) {
            $extension = strtolower($file->getExtension());

            if (! in_array($extension, $extensions, true)) {
                continue;
            }

            $relative = str_replace(DIRECTORY_SEPARATOR, '/', substr($file->getRealPath(), strlen($publicPath)));
            $urlPath = '/'.ltrim($relative, '/');

            if ($extension === 'css' && $skipCss) {
                $manifest[$urlPath] = null;

                continue;
            }

            $manifest[$urlPath] = $sri->hash((string) file_get_contents($file->getRealPath()));
        }

        foreach ((array) config('security.sri.warm_from_app', []) as $path) {
            $manifest['/'.ltrim((string) $path, '/')] = null;
        }

        $sri->write($manifest);

        $hashed = count(array_filter($manifest, fn ($v) => $v !== null));
        $pending = count($manifest) - $hashed;

        $this->info(sprintf(
            'Wrote %d entries to %s (%d hashed, %d pending warm-up).',
            count($manifest),
            $sri->manifestPath(),
            $hashed,
            $pending
        ));

        return self::SUCCESS;
    }
}
