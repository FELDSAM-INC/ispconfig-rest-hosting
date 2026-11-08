<?php

namespace IspconfigRestHosting\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\WebDomain;
use App\Services\WebPermissionService;
use App\Support\IspContext;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use IspconfigRestHosting\Services\LetsEncryptWaitService;

/** Spec 059: Let's Encrypt once the website's domain points to its server. */
final class LetsEncryptWaitController extends Controller
{
    public function show(WebDomain $webDomain, LetsEncryptWaitService $waits): JsonResponse
    {
        return response()->json($waits->view($webDomain), 200, ['Cache-Control' => 'private, no-store']);
    }

    public function update(Request $request, WebDomain $webDomain, LetsEncryptWaitService $waits): JsonResponse
    {
        $this->authorizeChange($webDomain);
        $body = $request->validate(['redirect_https' => ['sometimes', 'boolean']]);
        $waits->start($webDomain, (bool) ($body['redirect_https'] ?? false));

        return response()->json($waits->view($webDomain->refresh()), 200, ['Cache-Control' => 'private, no-store']);
    }

    public function destroy(WebDomain $webDomain, LetsEncryptWaitService $waits): Response
    {
        $this->authorizeChange($webDomain, false);
        $waits->cancel((int) $webDomain->getKey());

        return response()->noContent();
    }

    /** Website update permission, an unlocked account and, to start, SSL and Let's Encrypt in the plan. */
    private function authorizeChange(WebDomain $site, bool $start = true): void
    {
        $scope = app(IspContext::class)->authScope();
        if (! $scope->allows($site->getAttributes(), 'u')) {
            throw new AuthorizationException('You may not change this website.');
        }
        if (! $scope->isAdmin && DB::table('client')->join('sys_group', 'client.client_id', '=', 'sys_group.client_id')
            ->where('sys_group.groupid', $site->sys_groupid)->where('client.locked', 'y')->exists()) {
            throw new AuthorizationException('The account is locked; SSL settings cannot be changed.');
        }
        if ($start) {
            app(WebPermissionService::class)->assertCertificateOperation($scope, 'renew');
        }
    }
}
