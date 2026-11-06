<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

// Spec 048: per-client totals of a website and the bans of each web server, both written by the root WAF worker.
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('api_web_waf_clients', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedInteger('server_id');
            $table->unsignedInteger('website_id');
            $table->string('identity', 48);
            $table->string('client_ip', 45);
            $table->unsignedInteger('events')->default(0);
            $table->unsignedInteger('requests')->default(0);
            $table->unsignedInteger('over_threshold')->default(0);
            $table->unsignedBigInteger('first_seen');
            $table->unsignedBigInteger('last_seen');
            $table->unique(['server_id', 'website_id', 'identity', 'client_ip'], 'api_waf_clients_site_ip');
            $table->index('last_seen');
        });
        Schema::create('api_web_waf_bans', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedInteger('server_id');
            $table->string('client_ip', 45);
            $table->string('jail', 32);
            $table->string('reason', 16)->default('');
            $table->unsignedBigInteger('banned_at');
            $table->unsignedBigInteger('expires_at')->default(0);
            $table->unique(['server_id', 'client_ip'], 'api_waf_bans_server_ip');
        });
        Schema::table('api_web_waf_events', function (Blueprint $table): void {
            $table->index(['server_id', 'website_id', 'identity', 'client_ip', 'id'], 'api_waf_events_site_ip');
        });
    }

    public function down(): void
    {
        Schema::table('api_web_waf_events', function (Blueprint $table): void {
            $table->dropIndex('api_waf_events_site_ip');
        });
        Schema::dropIfExists('api_web_waf_bans');
        Schema::dropIfExists('api_web_waf_clients');
    }
};
