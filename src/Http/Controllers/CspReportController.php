<?php

namespace MakeDev\Security\Http\Controllers;

use MakeDev\Security\Models\CspReport;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Throwable;

class CspReportController extends Controller
{
    public function store(Request $request): Response
    {
        $payload = json_decode($request->getContent(), true);

        $report = $payload['csp-report'] ?? $payload;

        if (! is_array($report)) {
            return response()->noContent();
        }

        $channel = config('security.csp.report.channel') ?: config('logging.default');
        $storeInDb = (bool) config('security.csp.report.store_in_db', true);

        $record = [
            'blocked_uri' => $this->string($report, 'blocked-uri'),
            'violated_directive' => $this->string($report, 'violated-directive'),
            'effective_directive' => $this->string($report, 'effective-directive'),
            'document_uri' => $this->string($report, 'document-uri'),
            'referrer' => $this->string($report, 'referrer'),
            'disposition' => $this->string($report, 'disposition'),
            'source_file' => $this->string($report, 'source-file'),
            'line_number' => $this->integer($report, 'line-number'),
            'column_number' => $this->integer($report, 'column-number'),
            'status_code' => $this->integer($report, 'status-code'),
            'script_sample' => $this->string($report, 'script-sample'),
            'user_agent' => $request->userAgent(),
        ];

        // Browsers omit source-file when it equals document-uri (CSP3 §5.4),
        // which makes inline-violation rows look empty in SQL viewers. Fill
        // it back in so source_file always points at a useful URL.
        if ($record['source_file'] === null && $record['blocked_uri'] === 'inline') {
            $record['source_file'] = $record['document_uri'];
        }

        Log::channel($channel)->warning('CSP violation', $record);

        if ($storeInDb) {
            $this->persist($record + ['ip' => $request->ip()]);
        }

        return response()->noContent();
    }

    private function string(array $report, string $key): ?string
    {
        $value = $report[$key] ?? null;

        return is_string($value) && $value !== '' ? mb_substr($value, 0, 2048) : null;
    }

    private function integer(array $report, string $key): ?int
    {
        $value = $report[$key] ?? null;

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && ctype_digit($value)) {
            return (int) $value;
        }

        return null;
    }

    private function persist(array $record): void
    {
        try {
            CspReport::create($record);
        } catch (Throwable $e) {
            Log::warning('Failed to persist CSP report', [
                'error' => $e->getMessage(),
            ]);
        }
    }
}
