<?php

namespace App\Http\Middleware;

use App\Models\ApplicationDeploymentQueue;
use App\Models\Environment;
use App\Models\PersonalAccessToken;
use App\Models\Project;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Restricts an API token that is scoped to specific environments.
 *
 * Unscoped tokens (the default) are untouched. Scoped tokens may only reach
 * resources that live inside one of their allowed environments:
 *  - applications / databases / services are resolved through their UUID and
 *    checked against the scope (403 when outside it);
 *  - the main list endpoints are filtered inside their controllers instead;
 *  - deploy endpoints are enforced inside DeployController so tag-based
 *    deployments can be filtered too;
 *  - the MCP endpoint defers to the MCP tool layer (ResolvesTeam) which
 *    enforces the same scope per tool;
 *  - every other (team-level) endpoint is denied.
 */
class EnforceApiTokenEnvironmentScope
{
    /**
     * List endpoints filtered to the token scope inside their controllers.
     *
     * @var array<int, string>
     */
    private const FILTERED_LIST_ROUTES = [
        'v1/applications',
        'v1/databases',
        'v1/services',
        'v1/resources',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->user()?->currentAccessToken();

        if (! $token instanceof PersonalAccessToken || ! $token->isEnvironmentScoped()) {
            return $next($request);
        }

        $route = $request->route();
        if ($route === null) {
            return $next($request);
        }

        $uri = trim($route->uri(), '/');

        // Strip the "api/" prefix so the version segment leads the path.
        $segments = explode('/', $uri);
        if (($segments[0] ?? null) === 'api') {
            array_shift($segments);
            $uri = implode('/', $segments);
        }

        if (in_array($uri, self::FILTERED_LIST_ROUTES, true)) {
            return $next($request);
        }

        $environmentId = $this->resolveEnvironmentId($request, $uri);

        // `true` means the route is enforced further down the stack (deploy).
        if ($environmentId === true) {
            return $next($request);
        }

        if (is_int($environmentId) && $token->allowsEnvironment($environmentId)) {
            return $next($request);
        }

        return $this->deny($request);
    }

    /**
     * @return int|bool Environment id, `true` to defer, or `false` to deny.
     */
    private function resolveEnvironmentId(Request $request, string $uri): int|bool
    {
        // MCP tools enforce the environment scope themselves (ResolvesTeam).
        if ($uri === 'mcp' || str_starts_with($uri, 'mcp/')) {
            return true;
        }

        $parts = explode('/', $uri);
        $resource = $parts[1] ?? null;

        return match ($resource) {
            'applications',
            'databases',
            'services' => $this->environmentIdForResource($request->route('uuid')),
            'deployments' => $this->resolveDeploymentRoute($request, $parts),
            'projects' => $this->resolveProjectRoute($request),
            // Handled inside DeployController so tags can be filtered too.
            'deploy' => true,
            default => false,
        };
    }

    /**
     * Resolve the environment of a top-level resource (application, database or service).
     */
    private function environmentIdForResource(mixed $uuid): int|bool
    {
        $uuid = is_string($uuid) && $uuid !== '' ? $uuid : null;
        $teamId = getTeamIdFromToken();

        if ($uuid === null || is_null($teamId)) {
            return false;
        }

        $resource = getResourceByUuid($uuid, (int) $teamId);
        if (! $resource) {
            return false;
        }

        $environmentId = $resource->environment_id ?? $resource->service?->environment_id;

        return is_null($environmentId) ? false : (int) $environmentId;
    }

    /**
     * `/deployments/applications/{uuid}` resolves through the application, while
     * `/deployments/{uuid}` (and its cancel action) resolve through the deployment.
     *
     * @param  array<int, string>  $parts
     */
    private function resolveDeploymentRoute(Request $request, array $parts): int|bool
    {
        if (($parts[2] ?? null) === 'applications') {
            return $this->environmentIdForResource($request->route('uuid'));
        }

        $deploymentUuid = $request->route('uuid');
        if (! is_string($deploymentUuid) || $deploymentUuid === '') {
            return false;
        }

        $application = ApplicationDeploymentQueue::where('deployment_uuid', $deploymentUuid)->first()?->application;
        $environmentId = $application?->environment_id;

        return is_null($environmentId) ? false : (int) $environmentId;
    }

    /**
     * Allow the environment-scoped project routes, deny the project-level ones.
     */
    private function resolveProjectRoute(Request $request): int|bool
    {
        $environmentParam = $request->route('environment_name_or_uuid');
        $projectUuid = $request->route('uuid');
        $teamId = getTeamIdFromToken();

        if (! $environmentParam || ! is_string($projectUuid) || is_null($teamId)) {
            return false;
        }

        $project = Project::where('team_id', $teamId)->where('uuid', $projectUuid)->first();
        if (! $project) {
            return false;
        }

        $environment = Environment::where('project_id', $project->id)
            ->where(function ($query) use ($environmentParam) {
                $query->where('uuid', $environmentParam)
                    ->orWhere('name', $environmentParam);
            })
            ->first();

        return $environment?->id ?? false;
    }

    private function deny(Request $request): Response
    {
        $message = 'This API token is restricted to specific environments and cannot access this resource.';

        if ($request->is('mcp') || $request->is('mcp/*')) {
            return response()->json([
                'jsonrpc' => '2.0',
                'id' => $request->input('id'),
                'error' => [
                    'code' => -32003,
                    'message' => $message,
                ],
            ]);
        }

        return response()->json(['message' => $message], 403);
    }
}
