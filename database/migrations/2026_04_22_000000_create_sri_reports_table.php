<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! config('security.sri.report.store_in_db', true)) {
            return;
        }

        Schema::connection($this->connection())->create($this->table(), function (Blueprint $table) {
            $table->id();
            $table->text('url')->nullable();
            $table->string('tag', 16)->nullable();
            $table->string('integrity', 255)->nullable();
            $table->text('document_uri')->nullable();
            $table->text('referrer')->nullable();
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
        return config('security.sri.report.connection');
    }

    private function table(): string
    {
        return (string) config('security.sri.report.table', 'sri_reports');
    }
};
