<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! config('security.csp.report.store_in_db', true)) {
            return;
        }

        Schema::connection($this->connection())->create($this->table(), function (Blueprint $table) {
            $table->id();
            $table->text('blocked_uri')->nullable();
            $table->string('violated_directive', 255)->nullable();
            $table->string('effective_directive', 255)->nullable();
            $table->text('document_uri')->nullable();
            $table->text('referrer')->nullable();
            $table->string('disposition', 32)->nullable();
            $table->text('source_file')->nullable();
            $table->unsignedInteger('line_number')->nullable();
            $table->unsignedInteger('column_number')->nullable();
            $table->unsignedSmallInteger('status_code')->nullable();
            $table->text('script_sample')->nullable();
            $table->text('user_agent')->nullable();
            $table->string('ip', 45)->nullable();
            $table->timestamp('created_at')->useCurrent();
            $table->index('created_at');
        });
    }

    public function down(): void
    {
        Schema::connection($this->connection())->dropIfExists($this->table());
    }

    public function getConnection(): ?string
    {
        return $this->connection();
    }

    private function connection(): ?string
    {
        return config('security.csp.report.connection');
    }

    private function table(): string
    {
        return (string) config('security.csp.report.table', 'csp_reports');
    }
};
