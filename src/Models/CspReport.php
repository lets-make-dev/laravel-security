<?php

namespace MakeDev\Security\Models;

use Illuminate\Database\Eloquent\Model;

class CspReport extends Model
{
    const UPDATED_AT = null;

    protected $guarded = [];

    protected $casts = [
        'created_at' => 'datetime',
        'line_number' => 'integer',
        'column_number' => 'integer',
        'status_code' => 'integer',
    ];

    public function getTable(): string
    {
        return (string) config('security.csp.report.table', 'csp_reports');
    }

    public function getConnectionName(): ?string
    {
        return config('security.csp.report.connection') ?? parent::getConnectionName();
    }
}
