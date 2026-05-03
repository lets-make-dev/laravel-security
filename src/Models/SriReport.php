<?php

namespace MakeDev\Security\Models;

use Illuminate\Database\Eloquent\Model;

class SriReport extends Model
{
    const UPDATED_AT = null;

    protected $guarded = [];

    protected $casts = [
        'created_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return (string) config('security.sri.report.table', 'sri_reports');
    }

    public function getConnectionName(): ?string
    {
        return config('security.sri.report.connection') ?? parent::getConnectionName();
    }
}
