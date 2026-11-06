<?php

namespace IspconfigRestHosting\Services;

use App\Models\WebDomain;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use IspconfigRestHosting\Support\WebWafAudit;
use IspconfigRestHosting\Support\WebWafBans;
use IspconfigRestHosting\Support\WebWafPolicy;
use IspconfigRestHosting\Support\WebWafProfiles;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;

final class WebWafService
{
    private array $workers = [];

    private ?bool $hasWorkers = null;

    public function worker(WebDomain $site): ?object
    {
        if (! ($this->hasWorkers ??= Schema::hasTable('api_web_waf_workers'))) {
            return null;
        }

        $key = $site->server_id.':'.$site->web_server_type;
        if (array_key_exists($key, $this->workers)) {
            return $this->workers[$key];
        }

        return $this->workers[$key] = DB::table('api_web_waf_workers')->where('server_id', $site->server_id)->where('engine', $site->web_server_type)->where('heartbeat', '>=', time() - 150)->first();
    }

    public function available(WebDomain $site): bool
    {
        return $this->worker($site) !== null || str_contains((string) $site->getAttribute($site->web_server_type.'_directives'), WebWafPolicy::BEGIN);
    }

    public function settings(WebDomain $site): ?array
    {
        try {
            return WebWafPolicy::extract((string) $site->getAttribute($site->web_server_type.'_directives'), WebWafPolicy::identity($site->getAttributes()));
        } catch (InvalidArgumentException $e) {
            throw new ConflictHttpException($e->getMessage());
        }
    }

    /** off, detection or enforcing for list badges; null when the managed block was changed outside the API. */
    public function mode(WebDomain $site): ?string
    {
        try {
            $settings = $this->settings($site);
        } catch (ConflictHttpException) {
            return null;
        }

        return $settings === null || ! $settings['enabled'] ? 'off' : $settings['mode'];
    }

    public function view(WebDomain $site): array
    {
        $worker = $this->worker($site);
        $settings = $this->settings($site);

        return ['revision' => $this->revision($site), 'available' => $worker !== null, 'application_profiles' => $this->profiles($worker), 'atomic_available' => (bool) ($worker->atomic_available ?? false), 'engine' => $worker->engine ?? null,
            'rules_version' => $worker->rules_version ?? null, 'configured' => $settings !== null, 'settings' => $settings ?? WebWafPolicy::DEFAULTS];
    }

    private function profiles(?object $worker): array
    {
        $reported = json_decode($worker->application_profiles ?? 'null', true);

        return ['none', ...array_values(array_filter(array_keys(WebWafProfiles::PLUGINS), static fn ($profile) => is_array($reported) && in_array($profile, $reported, true)))];
    }

    public function revision(WebDomain $site): string
    {
        return hash('sha256', (string) $site->getAttribute($site->web_server_type.'_directives'));
    }

    public function update(WebDomain $site, array $changes): void
    {
        if (isset($changes['expected_revision']) && ! hash_equals($this->revision($site), $changes['expected_revision'])) {
            throw new ConflictHttpException('WAF settings changed. Reload and try again.');
        }
        unset($changes['expected_revision']);
        $worker = $this->worker($site);
        $previous = $this->settings($site) ?? WebWafPolicy::DEFAULTS;
        try {
            $settings = WebWafPolicy::normalize(array_replace($previous, $changes));
        } catch (InvalidArgumentException $e) {
            throw ValidationException::withMessages(['waf' => $e->getMessage()]);
        }
        if ($settings['enabled'] && ! $worker) {
            throw ValidationException::withMessages(['waf' => 'The WAF server tool is unavailable.']);
        }
        if (! in_array($settings['application_profile'], $this->profiles($worker), true)
            && ($settings['enabled'] || $settings['application_profile'] !== $previous['application_profile'])) {
            throw ValidationException::withMessages(['application_profile' => 'This application profile is not available on the website server.']);
        }
        if ($settings['enabled'] && $settings['atomic'] && ! $worker->atomic_available) {
            throw ValidationException::withMessages(['atomic' => 'Atomicorp rules are not configured on this server.']);
        }
        $field = $site->web_server_type.'_directives';
        try {
            $site->setAttribute($field, WebWafPolicy::replace((string) $site->getAttribute($field), WebWafPolicy::compile($site->getAttributes(), $site->web_server_type, $settings)));
        } catch (InvalidArgumentException $e) {
            throw new ConflictHttpException($e->getMessage());
        }
        if (strlen($site->getAttribute($field)) > 60000) {
            throw ValidationException::withMessages(['waf' => 'The generated configuration is too large.']);
        }
        $site->save();
    }

    /** Renames get a fresh log identity; transfers reset the former owner's exceptions. */
    public function refreshIdentity(WebDomain $site): void
    {
        if (! $site->isDirty(['domain', 'server_id', 'sys_groupid'])) {
            return;
        }
        $old = $site->getRawOriginal();
        foreach (['apache', 'nginx'] as $engine) {
            $field = $engine.'_directives';
            if (! str_contains((string) $site->getAttribute($field), WebWafPolicy::BEGIN)) {
                continue;
            }
            try {
                $settings = WebWafPolicy::extract((string) $old[$field], WebWafPolicy::identity($old));
                if ($settings === null) {
                    throw new InvalidArgumentException('The managed WAF configuration changed.');
                }
                if ($site->isDirty(['server_id', 'sys_groupid'])) {
                    $settings = WebWafPolicy::DEFAULTS;
                }
                $site->setAttribute($field, WebWafPolicy::replace((string) $site->getAttribute($field), WebWafPolicy::compile($site->getAttributes(), $engine, $settings)));
            } catch (InvalidArgumentException $e) {
                throw new ConflictHttpException($e->getMessage());
            }
        }
    }

    public function events(WebDomain $site, array $filters): array
    {
        $query = DB::table('api_web_waf_events')->where('website_id', $site->getKey())->where('server_id', $site->server_id)->where('identity', WebWafPolicy::identity($site->getAttributes()));
        foreach (['outcome', 'rule_id'] as $field) {
            if (isset($filters[$field])) {
                $query->where($field, $filters[$field]);
            }
        }
        $bans = $this->bans($site);
        $limit = (int) ($filters['limit'] ?? 50);
        $offset = (int) ($filters['offset'] ?? 0);
        if (isset($filters['client_ip']) || isset($filters['banned'])) {
            // The worker keeps at most 1,000 events per website, so address blocks and bans are matched here.
            $rows = $query->orderByDesc('id')->get()->filter(fn ($row): bool => $this->matches($row->client_ip, $filters, $bans))->values();
            $total = $rows->count();
            $rows = $rows->slice($offset, $limit);
        } else {
            $total = $query->count();
            $rows = $query->orderByDesc('id')->offset($offset)->limit($limit)->get();
        }
        $data = $rows->map(function ($row) use ($bans): array {
            return ['id' => (int) $row->id, 'occurred_at' => gmdate('Y-m-d\TH:i:s\Z', $row->occurred_at), 'rule_id' => (int) $row->rule_id,
                'outcome' => $row->outcome, 'client_ip' => $row->client_ip, 'client_banned' => isset($bans[WebWafBans::canonical($row->client_ip)]),
                'method' => $row->method, 'path' => $row->path, 'parameter' => $row->parameter,
                'message' => str_contains($row->message, '[value]') ? WebWafAudit::description((int) $row->rule_id, $row->message) : $row->message, 'severity' => $row->severity, 'source' => $row->source];
        })->values()->all();

        return ['data' => $data, 'meta' => ['total' => $total, 'limit' => $limit, 'offset' => $offset]];
    }

    /** The website's clients with their totals over the last 7 days and their ban on its server (spec 048). */
    public function clients(WebDomain $site, array $filters): array
    {
        $limit = (int) ($filters['limit'] ?? 50);
        $offset = (int) ($filters['offset'] ?? 0);
        if (! Schema::hasTable('api_web_waf_clients')) {
            return ['data' => [], 'meta' => ['total' => 0, 'limit' => $limit, 'offset' => $offset]];
        }
        $bans = $this->bans($site);
        $query = DB::table('api_web_waf_clients')->where('website_id', $site->getKey())->where('server_id', $site->server_id)
            ->where('identity', WebWafPolicy::identity($site->getAttributes()))->orderByDesc('requests')->orderByDesc('last_seen')->orderBy('id');
        $rows = $query->get()->filter(fn ($row): bool => $this->matches($row->client_ip, $filters, $bans))->values();
        $data = $rows->slice($offset, $limit)->map(function ($row) use ($bans): array {
            $ban = $bans[WebWafBans::canonical($row->client_ip)] ?? null;

            return ['client_ip' => $row->client_ip, 'events' => (int) $row->events, 'requests' => (int) $row->requests,
                'over_threshold' => (int) $row->over_threshold, 'first_seen' => gmdate('Y-m-d\TH:i:s\Z', $row->first_seen),
                'last_seen' => gmdate('Y-m-d\TH:i:s\Z', $row->last_seen), 'ban' => $ban === null ? null : [
                    'reason' => in_array($ban->reason, ['attack', 'scan', 'repeat'], true) ? $ban->reason : 'other',
                    'banned_at' => gmdate('Y-m-d\TH:i:s\Z', $ban->banned_at),
                    'expires_at' => $ban->expires_at > 0 ? gmdate('Y-m-d\TH:i:s\Z', $ban->expires_at) : null]];
        })->values()->all();

        return ['data' => $data, 'meta' => ['total' => $rows->count(), 'limit' => $limit, 'offset' => $offset]];
    }

    /** Current bans of the website's server by canonical address. */
    private function bans(WebDomain $site): array
    {
        if (! Schema::hasTable('api_web_waf_bans')) {
            return [];
        }
        $bans = [];
        foreach (DB::table('api_web_waf_bans')->where('server_id', $site->server_id)->where(fn ($query) => $query->where('expires_at', 0)->orWhere('expires_at', '>', time()))->get() as $ban) {
            $bans[WebWafBans::canonical($ban->client_ip)] = $ban;
        }

        return $bans;
    }

    private function matches(string $ip, array $filters, array $bans): bool
    {
        if (isset($filters['client_ip']) && ! WebWafBans::contains($filters['client_ip'], $ip)) {
            return false;
        }

        return ! isset($filters['banned']) || isset($bans[WebWafBans::canonical($ip)]) === $filters['banned'];
    }
}
