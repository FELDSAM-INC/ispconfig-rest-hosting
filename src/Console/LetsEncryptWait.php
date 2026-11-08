<?php

namespace IspconfigRestHosting\Console;

use Illuminate\Console\Command;
use IspconfigRestHosting\Services\LetsEncryptWaitService;

/** Spec 059: the due Let's Encrypt waits; scheduled every minute. */
final class LetsEncryptWait extends Command
{
    protected $signature = 'letsencrypt:wait {--limit=50 : Waits checked in one run}';

    protected $description = "Check the websites waiting for their domain to point to them and request Let's Encrypt when it does";

    public function handle(LetsEncryptWaitService $waits): int
    {
        $count = $waits->runDue(max(1, (int) $this->option('limit')));
        if ($this->output->isVerbose()) {
            $this->line("Checked {$count} waits.");
        }

        return self::SUCCESS;
    }
}
