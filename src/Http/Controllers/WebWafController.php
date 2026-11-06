<?php

namespace IspconfigRestHosting\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\WebDomain;
use App\Support\IspContext;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use IspconfigRestHosting\Http\Requests\UpdateWebWafRequest;
use IspconfigRestHosting\Services\WebWafService;
use IspconfigRestHosting\Support\WebWafBans;

final class WebWafController extends Controller
{
    public function show(WebDomain $webDomain, WebWafService $waf): JsonResponse
    {
        return response()->json($waf->view($webDomain), 200, ['Cache-Control' => 'private, no-store']);
    }

    public function update(UpdateWebWafRequest $request, WebDomain $webDomain, WebWafService $waf): JsonResponse
    {
        $site = DB::transaction(function () use ($request, $webDomain, $waf): WebDomain {
            $site = WebDomain::query()->readable()->whereKey($webDomain->getKey())->lockForUpdate()->firstOrFail();
            $scope = app(IspContext::class)->authScope();
            if (! $scope->isAdmin && DB::table('client')->join('sys_group', 'client.client_id', '=', 'sys_group.client_id')->where('sys_group.groupid', $site->sys_groupid)->where('client.locked', 'y')->exists()) {
                throw new AuthorizationException('The account is locked; WAF settings cannot be changed.');
            }
            $waf->update($site, $request->validated());

            return $site;
        });

        return response()->json($waf->view($site), 200, ['Cache-Control' => 'private, no-store']);
    }

    public function index(Request $request, WebDomain $webDomain, WebWafService $waf): JsonResponse
    {
        $filters = $request->validate(['limit' => ['sometimes', 'integer', 'min:1', 'max:100'], 'offset' => ['sometimes', 'integer', 'min:0', 'max:10000'],
            'outcome' => ['sometimes', Rule::in(['blocked', 'detected'])], 'rule_id' => ['sometimes', 'integer', 'min:1', 'max:2147483647']] + self::clientRules());

        return response()->json($waf->events($webDomain, self::clientFilters($filters)), 200, ['Cache-Control' => 'private, no-store']);
    }

    public function clients(Request $request, WebDomain $webDomain, WebWafService $waf): JsonResponse
    {
        $filters = $request->validate(['limit' => ['sometimes', 'integer', 'min:1', 'max:100'], 'offset' => ['sometimes', 'integer', 'min:0', 'max:10000']] + self::clientRules());

        return response()->json($waf->clients($webDomain, self::clientFilters($filters)), 200, ['Cache-Control' => 'private, no-store']);
    }

    /** `client_ip`: an address or CIDR block; `banned`: true/false/1/0 (spec 048). */
    private static function clientRules(): array
    {
        return ['client_ip' => ['sometimes', 'string', 'max:49', function (string $attribute, mixed $value, \Closure $fail): void {
            if (! is_string($value) || WebWafBans::block($value) === null) {
                $fail('Use an IP address or a CIDR block.');
            }
        }], 'banned' => ['sometimes', Rule::in(['true', 'false', '1', '0', true, false, 1, 0])]];
    }

    private static function clientFilters(array $filters): array
    {
        if (array_key_exists('banned', $filters)) {
            $filters['banned'] = in_array($filters['banned'], ['true', '1', true, 1], true);
        }

        return $filters;
    }
}
