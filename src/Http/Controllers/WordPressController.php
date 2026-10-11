<?php

namespace IspconfigRestHosting\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\WebDomain;
use Illuminate\Http\JsonResponse;
use IspconfigRestHosting\Http\Requests\StoreWordPressJobRequest;
use IspconfigRestHosting\Services\WordPressService;

final class WordPressController extends Controller
{
    public function show(WebDomain $webDomain, WordPressService $wordpress): JsonResponse
    {
        return response()->json($wordpress->view($webDomain), 200, ['Cache-Control' => 'private, no-store']);
    }

    public function store(StoreWordPressJobRequest $request, WebDomain $webDomain, WordPressService $wordpress): JsonResponse
    {
        return response()->json($wordpress->create($webDomain, $request->validated()), 201, ['Cache-Control' => 'private, no-store']);
    }

    public function job(WebDomain $webDomain, string $job, WordPressService $wordpress): JsonResponse
    {
        return response()->json($wordpress->job($webDomain, $job), 200, ['Cache-Control' => 'private, no-store']);
    }
}
