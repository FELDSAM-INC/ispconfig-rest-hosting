<?php

namespace IspconfigRestHosting\Services;

use App\Models\WebDomain;
use App\Services\TlsCertificateProbe;
use App\Services\WebDomainService;
use App\Services\WebPermissionService;
use App\Support\IspContext;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use IspconfigRestHosting\Support\DnsLookup;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Throwable;

/**
 * Let's Encrypt once the website's domain points to its server (spec 059).
 *
 * ISPConfig 3.3 requests the certificate only while it processes the change that enables Let's Encrypt. Names that do
 * not reach the server yet are left out, and with none left Let's Encrypt is switched off again, without a retry
 * (letsencrypt.inc.php assemble_domains_to_request, apache2_plugin/nginx_plugin). A wait keeps the request here: public
 * resolvers are asked until the preferred name points to the website's server, then Let's Encrypt is enabled through
 * the normal website update. Names that still point elsewhere are added later with a renewal.
 *
 * States: waiting (for DNS), issuing (ISPConfig processes the request), extending (issued; more names are watched),
 * completed, expired, failed. A website rename, transfer, deletion or a manual SSL change ends the wait.
 */
class LetsEncryptWaitService
{
    public const TABLE = 'api_letsencrypt_waits';

    public const ACTIVE = ['waiting', 'issuing', 'extending'];

    public const TYPES = ['vhost', 'vhostsubdomain', 'vhostalias'];

    /** seo_redirect values whose visitors end on www. */
    public const WWW_REDIRECTS = ['non_www_to_www', '*_domain_tld_to_www_domain_tld', '*_to_www_domain_tld'];

    /** The service writes the website itself: the hook must not end the wait. */
    private bool $writing = false;

    /** @var array<int, string>|null website id => state, for website listings */
    private ?array $states = null;

    public function __construct(private readonly DnsLookup $dns, private readonly TlsCertificateProbe $probe) {}

    /** The wait state for the website attribute; null without a wait. */
    public function state(WebDomain $site): ?string
    {
        $this->states ??= DB::table(self::TABLE)->pluck('state', 'website_id')->map(fn ($state): string => (string) $state)->all();

        return $this->states[(int) $site->getKey()] ?? null;
    }

    /** @return array<string, mixed> */
    public function view(WebDomain $site): array
    {
        $row = DB::table(self::TABLE)->where('website_id', $site->getKey())->first();
        $raw = $site->getAttributes();
        $certified = $row !== null ? (json_decode((string) $row->certificate_names, true) ?: []) : [];
        $names = [];
        foreach ($row !== null ? (json_decode((string) $row->names, true) ?: []) : [] as $name) {
            $names[] = $name + ['certified' => self::covers($certified, $name['name'])];
        }
        $time = fn ($value): ?string => $value !== null ? gmdate('c', (int) $value) : null;

        return [
            'state' => $row->state ?? 'none',
            'reason' => $row->reason ?? null,
            'redirect_https' => (bool) ($row->redirect_https ?? false),
            'started_at' => $time($row->started_at ?? null),
            'expires_at' => $time($row->expires_at ?? null),
            'last_checked_at' => $time($row->last_checked_at ?? null),
            'next_check_at' => $row !== null && in_array($row->state, self::ACTIVE, true) ? $time($row->next_check_at) : null,
            'finished_at' => $time($row->finished_at ?? null),
            'failures' => (int) ($row->failures ?? 0),
            'expected_addresses' => $this->expected($raw),
            'names' => $names,
        ];
    }

    /**
     * Start (or restart) a wait and check once right away: with the domain already pointing to the server, Let's
     * Encrypt is enabled in the same request. Runs as the requesting account; the caller checked its permissions.
     */
    public function start(WebDomain $site, bool $redirectHttps): void
    {
        $raw = $site->getAttributes();
        if (! in_array($raw['type'] ?? '', self::TYPES, true)) {
            throw ValidationException::withMessages(['website' => "Let's Encrypt certificates are requested for websites, not for their aliases or subdomains."]);
        }
        if (($raw['active'] ?? 'n') !== 'y') {
            throw new ConflictHttpException('The website is disabled.');
        }
        if ($this->expected($raw) === []) {
            throw new ConflictHttpException("The website's server has no public IP address to compare the domain with.");
        }
        $context = app(IspContext::class);
        $now = time();
        DB::transaction(function () use ($site, $raw, $redirectHttps, $context, $now): void {
            DB::table(self::TABLE)->where('website_id', $site->getKey())->delete();
            DB::table(self::TABLE)->insert([
                'website_id' => $site->getKey(), 'server_id' => (int) $raw['server_id'], 'sys_groupid' => (int) $raw['sys_groupid'],
                'domain' => (string) $raw['domain'], 'actor_userid' => $context->sysUserId(), 'actor_groupid' => $context->sysGroupId(),
                'state' => 'waiting', 'redirect_https' => $redirectHttps, 'started_at' => $now,
                'expires_at' => $now + (int) config('letsencrypt_wait.expires_after'), 'next_check_at' => $now,
            ]);
        });
        $this->states = null;
        $this->advance((int) $site->getKey(), false);
    }

    public function cancel(int $websiteId): void
    {
        DB::table(self::TABLE)->where('website_id', $websiteId)->delete();
        $this->states = null;
    }

    /** Hook: a manual SSL change, a rename or a transfer of the website ends its wait. */
    public function siteChanging(WebDomain $site, string $action): void
    {
        if ($this->writing || $action !== 'update') {
            return;
        }
        $flag = fn (string $field, $value): string => ($value ?? 'n') === 'y' || $value === true ? 'y' : 'n';
        $ssl = array_filter(['ssl', 'ssl_letsencrypt'], fn (string $field): bool => $flag($field, $site->getRawOriginal($field)) !== $flag($field, $site->getAttributes()[$field] ?? null));
        if ($ssl !== [] || $site->isDirty(['domain', 'server_id', 'sys_groupid'])) {
            $this->cancel((int) $site->getKey());
        }
    }

    /** Scheduler: the due waits, oldest first; finished ones are removed after a while. */
    public function runDue(int $limit = 50): int
    {
        $now = time();
        DB::table(self::TABLE)->whereNotIn('state', self::ACTIVE)->where('finished_at', '<', $now - (int) config('letsencrypt_wait.keep_finished'))->delete();
        $ids = DB::table(self::TABLE)->whereIn('state', self::ACTIVE)->where('next_check_at', '<=', $now)
            ->orderBy('next_check_at')->limit($limit)->pluck('website_id');
        foreach ($ids as $id) {
            try {
                $this->advance((int) $id, true);
            } catch (Throwable $e) {
                Log::warning("Let's Encrypt wait of website {$id} failed: ".get_class($e).': '.$e->getMessage());
                DB::table(self::TABLE)->where('website_id', $id)->update(['next_check_at' => $now + 300]);
            }
        }

        return count($ids);
    }

    /** One step of a wait. $asActor: outside a request, write as the account that started it. */
    public function advance(int $websiteId, bool $asActor): void
    {
        $row = DB::table(self::TABLE)->where('website_id', $websiteId)->first();
        if ($row === null || ! in_array($row->state, self::ACTIVE, true)) {
            return;
        }
        $site = WebDomain::query()->whereKey($websiteId)->first();
        $raw = $site?->getAttributes();
        if ($site === null || (int) $raw['server_id'] !== (int) $row->server_id || (int) $raw['sys_groupid'] !== (int) $row->sys_groupid
            || (string) $raw['domain'] !== (string) $row->domain) {
            $this->cancel($websiteId);

            return;
        }
        if ($asActor) {
            app(IspContext::class)->actAs((int) $row->actor_userid, (int) $row->actor_groupid);
        }
        $now = time();
        match ($row->state) {
            'waiting' => $this->waiting($row, $raw, $now),
            'issuing' => $this->issuing($row, $raw, $now),
            'extending' => $this->extending($row, $raw, $now),
        };
        $this->states = null;
    }

    private function waiting(object $row, array $raw, int $now): void
    {
        if ($now >= (int) $row->expires_at) {
            $this->store($row, ['state' => 'expired', 'reason' => 'not_pointing', 'finished_at' => $now]);

            return;
        }
        $expected = $this->expected($raw);
        if ($expected === []) {
            $this->store($row, ['reason' => 'no_public_address', 'last_checked_at' => $now, 'next_check_at' => $this->next($row, $now)]);

            return;
        }
        $names = $this->check($raw, $expected);
        $update = ['names' => json_encode($names), 'last_checked_at' => $now];
        $ready = array_filter($names, fn (array $name): bool => $name['required']) !== []
            && array_filter($names, fn (array $name): bool => $name['required'] && ! $name['points']) === [];
        if (! $ready) {
            $this->store($row, $update + ['next_check_at' => $this->next($row, $now)]);

            return;
        }
        if (! $this->planAllows($raw)) {
            $this->store($row, $update + ['state' => 'failed', 'reason' => 'not_in_plan', 'finished_at' => $now]);

            return;
        }
        $enabled = ($raw['ssl'] ?? 'n') === 'y' && ($raw['ssl_letsencrypt'] ?? 'n') === 'y';
        // Already issued for the preferred name (a restarted wait): no new certificate, only the names left out.
        $certified = $enabled ? $this->certificateNames($raw) : null;
        if ($certified !== null && self::covers($certified, $this->required($raw, $this->names($raw)))) {
            $missing = array_filter($names, fn (array $name): bool => ! self::covers($certified, $name['name']));
            $this->complete($row, $raw, $now, $certified, null, $missing !== [], $update);

            return;
        }
        try {
            $this->write($row, $update + ['state' => 'issuing', 'reason' => null, 'issuing_since' => $now, 'next_check_at' => $now + 60],
                fn (WebDomain $site) => $enabled ? app(WebDomainService::class)->renewLetsEncrypt($site)
                    : app(WebDomainService::class)->update($site, ['ssl' => true, 'ssl_letsencrypt' => true]));
        } catch (ValidationException) {
            // The website update refuses SSL here (one SSL website per IP address without SNI): retrying cannot help.
            $this->store($row, $update + ['state' => 'failed', 'reason' => 'rejected', 'finished_at' => $now]);
        }
    }

    private function issuing(object $row, array $raw, int $now): void
    {
        $processed = $row->datalog_id === null
            || (int) DB::table('server')->where('server_id', $raw['server_id'])->value('updated') >= (int) $row->datalog_id;
        $waited = $now - (int) $row->issuing_since;
        if (! $processed) {
            $waited > (int) config('letsencrypt_wait.issuing_timeout') ? $this->failed($row, 'stalled', $now) : $this->store($row, ['next_check_at' => $now + 60]);

            return;
        }
        // ISPConfig switches Let's Encrypt off when no name could be verified or issuance failed.
        if (($raw['ssl'] ?? 'n') !== 'y' || ($raw['ssl_letsencrypt'] ?? 'n') !== 'y') {
            $this->failed($row, 'issuance_failed', $now);

            return;
        }
        $names = array_column(json_decode((string) $row->names, true) ?: [], null, 'name');
        $certified = $this->certificateNames($raw);
        $required = array_keys(array_filter($names, fn (array $name): bool => $name['required']));
        if ($certified === null || array_filter($required, fn (string $name): bool => ! self::covers($certified, $name)) !== []) {
            // The web server may still present the previous certificate for a moment after ISPConfig's reload.
            if ($waited < 300) {
                $this->store($row, ['next_check_at' => $now + 60]);
            } elseif ($certified === null) {
                $this->complete($row, $raw, $now, [], 'certificate_unreadable');
            } else {
                $this->failed($row, 'issuance_failed', $now);
            }

            return;
        }
        $missing = array_filter(array_keys($names), fn (string $name): bool => ! self::covers($certified, $name));
        $this->complete($row, $raw, $now, $certified, null, $missing !== []);
    }

    private function extending(object $row, array $raw, int $now): void
    {
        if (($raw['ssl'] ?? 'n') !== 'y' || ($raw['ssl_letsencrypt'] ?? 'n') !== 'y') {
            $this->cancel((int) $row->website_id);

            return;
        }
        $certified = json_decode((string) $row->certificate_names, true) ?: [];
        $expected = $this->expected($raw);
        $names = $expected === [] ? [] : $this->check($raw, $expected);
        $update = ['names' => json_encode($names), 'last_checked_at' => $now];
        $missing = array_filter($names, fn (array $name): bool => ! self::covers($certified, $name['name']));
        if ($expected !== [] && $missing === []) {
            $this->store($row, $update + ['state' => 'completed', 'finished_at' => $now]);

            return;
        }
        if ($now >= (int) $row->expires_at) {
            $this->store($row, $update + ['state' => 'completed', 'reason' => 'partial', 'finished_at' => $now]);

            return;
        }
        $renewDue = $row->renewed_at === null || $now - (int) $row->renewed_at >= (int) config('letsencrypt_wait.renew_interval');
        if ($renewDue && array_filter($missing, fn (array $name): bool => $name['points']) !== []) {
            $this->write($row, $update + ['state' => 'issuing', 'issuing_since' => $now, 'renewed_at' => $now, 'next_check_at' => $now + 60],
                fn (WebDomain $site) => app(WebDomainService::class)->renewLetsEncrypt($site));

            return;
        }
        $this->store($row, $update + ['next_check_at' => $this->next($row, $now)]);
    }

    /** Issued: the HTTPS redirect the customer asked for, then either done or watching the names left out. */
    private function complete(object $row, array $raw, int $now, array $certified, ?string $reason, bool $extend = false, array $extra = []): void
    {
        $update = $extra + ['certificate_names' => json_encode(array_values($certified)), 'failures' => 0, 'reason' => $reason, 'issuing_since' => null]
            + ($extend ? ['state' => 'extending', 'next_check_at' => $this->next($row, $now)] : ['state' => 'completed', 'finished_at' => $now]);
        if ($row->redirect_https && ($raw['rewrite_to_https'] ?? 'n') !== 'y') {
            $this->write($row, $update, fn (WebDomain $site) => app(WebDomainService::class)->update($site, ['rewrite_to_https' => true]), false);

            return;
        }
        $this->store($row, $update);
    }

    private function failed(object $row, string $reason, int $now): void
    {
        $failures = (int) $row->failures + 1;
        $this->store($row, $failures >= (int) config('letsencrypt_wait.max_failures')
            ? ['state' => 'failed', 'reason' => $reason, 'failures' => $failures, 'finished_at' => $now, 'issuing_since' => null]
            : ['state' => 'waiting', 'reason' => $reason, 'failures' => $failures, 'issuing_since' => null, 'next_check_at' => $now + (int) config('letsencrypt_wait.retry_after_failure')]);
    }

    /** Store the step's result unless the wait changed meanwhile (restarted, cancelled or advanced elsewhere). */
    private function store(object $row, array $update): bool
    {
        return DB::table(self::TABLE)->where('website_id', $row->website_id)->where('version', $row->version)
            ->update($update + ['version' => (int) $row->version + 1]) === 1;
    }

    /** Write the website and the step together, with the website and the wait locked. */
    private function write(object $row, array $update, callable $change, bool $journal = true): void
    {
        DB::transaction(function () use ($row, $update, $change, $journal): void {
            $current = DB::table(self::TABLE)->where('website_id', $row->website_id)->where('version', $row->version)->lockForUpdate()->first();
            $site = WebDomain::query()->whereKey($row->website_id)->lockForUpdate()->first();
            if ($current === null || $site === null) {
                return;
            }
            $this->writing = true;
            try {
                $change($site);
            } finally {
                $this->writing = false;
            }
            if ($journal) {
                $update['datalog_id'] = DB::table('sys_datalog')->where('dbtable', 'web_domain')->where('dbidx', 'domain_id:'.$row->website_id)->max('datalog_id');
            }
            $this->store($row, $update);
        });
    }

    private function next(object $row, int $now): int
    {
        $age = $now - (int) $row->started_at;
        foreach (config('letsencrypt_wait.intervals') as [$until, $interval]) {
            if ($age < $until) {
                return min($now + $interval, max((int) $row->expires_at, $now + 60));
            }
        }

        return $now + 1800;
    }

    private function planAllows(array $raw): bool
    {
        $clientId = (int) DB::table('sys_group')->where('groupid', $raw['sys_groupid'])->value('client_id');
        if ($clientId === 0) {
            return true;
        }
        $flags = app(WebPermissionService::class)->forClient($clientId)['flags'];

        return ($flags['ssl'] ?? false) && ($flags['ssl_letsencrypt'] ?? false);
    }

    /**
     * The certificate's names as ISPConfig requests them (assemble_domains_to_request): the domain (a wildcard
     * website's base domain), www for www and wildcard websites, active subdomains and aliases not excluded.
     *
     * @return list<string>
     */
    public function names(array $raw): array
    {
        $main = strtolower((string) $raw['domain']);
        $main = str_starts_with($main, '*.') ? substr($main, 2) : $main;
        $names = [$main];
        if (! str_starts_with($main, 'www.') && in_array($raw['subdomain'] ?? '', ['www', '*'], true)) {
            $names[] = 'www.'.$main;
        }
        $children = DB::table('web_domain')->where('parent_domain_id', $raw['domain_id'])->where('active', 'y')->whereIn('type', ['subdomain', 'alias'])
            ->where('ssl_letsencrypt_exclude', '!=', 'y')->orderBy('type', 'desc')->orderBy('domain_id')->get(['domain', 'type', 'subdomain']);
        foreach ($children as $child) {
            $domain = strtolower((string) $child->domain);
            $names[] = $domain;
            if ($child->type === 'alias' && ! str_starts_with($domain, 'www.') && in_array($child->subdomain, ['www', '*'], true)) {
                $names[] = 'www.'.$domain;
            }
        }

        return array_slice(array_values(array_unique($names)), 0, 100);
    }

    /** The name visitors end on: www when the website redirects to it, otherwise the domain. */
    public function required(array $raw, array $names): string
    {
        $www = 'www.'.$names[0];

        return in_array($raw['seo_redirect'] ?? '', self::WWW_REDIRECTS, true) && in_array($www, $names, true) ? $www : $names[0];
    }

    /**
     * Public addresses the names must resolve to: the website's own IP address when it has one, otherwise its server's
     * server_ip addresses (shared or of the owner), or the configured addresses of that server.
     *
     * @return list<string>
     */
    public function expected(array $raw): array
    {
        $serverId = (int) ($raw['server_id'] ?? 0);
        $configured = config('letsencrypt_wait.server_addresses')[(string) $serverId] ?? null;
        if (is_array($configured)) {
            $addresses = array_filter($configured, 'is_string');
        } else {
            $clientId = (int) DB::table('sys_group')->where('groupid', $raw['sys_groupid'] ?? 0)->value('client_id');
            $addresses = DB::table('server_ip')->where('server_id', $serverId)->whereIn('client_id', [0, $clientId])->pluck('ip_address')->all();
        }
        $public = array_values(array_filter(array_map(fn ($ip): string => strtolower(trim((string) $ip)), $addresses),
            fn (string $ip): bool => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false));
        $result = [];
        foreach ([[$raw['ip_address'] ?? '', FILTER_FLAG_IPV4], [$raw['ipv6_address'] ?? '', FILTER_FLAG_IPV6]] as [$own, $family]) {
            $own = strtolower(trim((string) $own));
            $mine = array_filter($public, fn (string $ip): bool => filter_var($ip, FILTER_VALIDATE_IP, $family) !== false);
            if (filter_var($own, FILTER_VALIDATE_IP, $family | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                $mine = [$own];
            }
            array_push($result, ...array_map(fn (string $ip): string => (string) inet_ntop((string) inet_pton($ip)), $mine));
        }

        return array_values(array_unique($result));
    }

    /**
     * Ask the resolvers about every name. A name points to the server when enough resolvers answer (two, or all when
     * fewer are configured) and each of them returns IPv4 addresses that are all expected, and only expected IPv6
     * addresses: the certificate authority prefers IPv6.
     *
     * @return list<array{name: string, required: bool, points: bool, status: string, addresses: list<string>}>
     */
    public function check(array $raw, array $expected): array
    {
        $names = $this->names($raw);
        $required = $this->required($raw, $names);
        $resolvers = config('letsencrypt_wait.resolvers');
        $answers = $this->dns->lookup($names, $resolvers);
        $needed = min(2, count($resolvers));
        $result = [];
        foreach ($names as $name) {
            $answered = $agree = 0;
            $seen = [];
            $unresolved = true;
            foreach ($resolvers as $resolver) {
                $a = $answers[$resolver][$name]['A'] ?? 'timeout';
                $aaaa = $answers[$resolver][$name]['AAAA'] ?? 'timeout';
                if (! self::answered($a) || ! self::answered($aaaa)) {
                    continue;
                }
                $answered++;
                $a = is_array($a) ? $a : [];
                $aaaa = is_array($aaaa) ? $aaaa : [];
                array_push($seen, ...$a, ...$aaaa);
                $unresolved = $unresolved && $a === [] && $aaaa === [];
                $agree += (int) ($a !== [] && array_diff($a, $expected) === [] && array_diff($aaaa, $expected) === []);
            }
            $seen = array_values(array_unique($seen));
            sort($seen);
            $points = $answered >= $needed && $agree === $answered;
            $result[] = ['name' => $name, 'required' => $name === $required, 'points' => $points,
                'status' => $points ? 'points' : ($answered < $needed ? 'unknown' : ($unresolved ? 'unresolved' : 'elsewhere')), 'addresses' => $seen];
        }

        return $result;
    }

    private static function answered(array|string $result): bool
    {
        return is_array($result) || $result === 'nxdomain';
    }

    /**
     * Names of the valid certificate the website's server presents for its domain, read fresh: on the website's own IP
     * address, then on its server's name (as the core Let's Encrypt status does). Null when none can be read.
     *
     * @return list<string>|null
     */
    public function certificateNames(array $raw): ?array
    {
        $name = strtolower((string) $raw['domain']);
        $name = str_starts_with($name, '*.') ? substr($name, 2) : $name;
        $hosts = filter_var($raw['ip_address'] ?? '', FILTER_VALIDATE_IP) ? [(string) $raw['ip_address']] : [];
        $server = strtolower(trim((string) DB::table('server')->where('server_id', $raw['server_id'])->value('server_name')));
        if (preg_match('/\A[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\z/D', $server)) {
            $hosts[] = $server;
        }
        foreach (array_unique($hosts) as $host) {
            $pem = $this->probe->fetch($host, $name);
            $info = $pem !== null ? @openssl_x509_parse($pem) : false;
            if (! is_array($info) || (int) ($info['validTo_time_t'] ?? 0) <= time()) {
                continue;
            }
            $names = [];
            foreach (explode(',', (string) ($info['extensions']['subjectAltName'] ?? '')) as $entry) {
                if (str_starts_with($entry = strtolower(trim($entry)), 'dns:')) {
                    $names[] = substr($entry, 4);
                }
            }
            if (self::covers($names, $name)) {
                return array_values(array_unique($names));
            }
        }

        return null;
    }

    /** Whether a certificate with these names is valid for $name, exactly or through a one-label wildcard. */
    public static function covers(array $certified, string $name): bool
    {
        foreach ($certified as $entry) {
            if ($entry === $name || (str_starts_with($entry, '*.') && substr_count($name, '.') === substr_count($entry, '.') && str_ends_with($name, substr($entry, 1)))) {
                return true;
            }
        }

        return false;
    }
}
