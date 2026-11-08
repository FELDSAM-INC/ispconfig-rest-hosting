<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

// Spec 059: websites waiting until their domain points to their server before Let's Encrypt is requested.
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('api_letsencrypt_waits', function (Blueprint $table): void {
            $table->unsignedInteger('website_id')->primary();
            // The website it was started for: a rename or transfer ends the wait.
            $table->unsignedInteger('server_id');
            $table->unsignedInteger('sys_groupid');
            $table->string('domain', 255);
            // Changes are written as the account that started the wait.
            $table->unsignedInteger('actor_userid');
            $table->unsignedInteger('actor_groupid');
            $table->string('state', 16);
            $table->string('reason', 32)->nullable();
            $table->boolean('redirect_https')->default(false);
            $table->unsignedInteger('version')->default(0);
            $table->unsignedTinyInteger('failures')->default(0);
            $table->unsignedBigInteger('datalog_id')->nullable();
            $table->unsignedBigInteger('started_at');
            $table->unsignedBigInteger('expires_at');
            $table->unsignedBigInteger('next_check_at');
            $table->unsignedBigInteger('last_checked_at')->nullable();
            $table->unsignedBigInteger('issuing_since')->nullable();
            $table->unsignedBigInteger('renewed_at')->nullable();
            $table->unsignedBigInteger('finished_at')->nullable();
            $table->text('names')->nullable();
            $table->text('certificate_names')->nullable();
            $table->index(['state', 'next_check_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('api_letsencrypt_waits');
    }
};
