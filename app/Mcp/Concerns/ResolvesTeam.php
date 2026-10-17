<?php

namespace App\Mcp\Concerns;

use App\Models\ApplicationDeploymentQueue;
use App\Models\Environment;
use App\Models\Project;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;

trait ResolvesTeam
{
    /**
     * Abilities that team members must not exercise (parity with ApiAbility).
     *
     * @var array<int, string>
     */
    private const MEMBER_DISALLOWED_ABILITIES = [
        'root',
        'write',
        'write:sensitive',
        'deploy',
        'read:sensitive',
    ];

    /**
     * Team-level MCP tools that an environment-scoped token may never call.
     *
     * @var array<int, string>
     */
    private const SCOPE_TEAM_LEVEL_TOOLS = [
        'get_current_team',
        'get_infrastructure_overview',
        'list_team_members',
        'list_servers',
        'get_server',
        'get_server_domains',
        'get_server_resources',
        'list_destinations',
        'get_destination',
        'list_projects',
        'get_project',
        'list_tags',
        'list_github_apps',
        'list_github_repositories',
        'list_github_branches',
        'list_shared_env_keys',
    ];

    /**
     * Resource-level MCP tools whose target environment is checked centrally.
     *
     * @var array<int, string>
     */
    private const SCOPE_RESOURCE_TOOLS = [
        'get_application',
        'get_database',
        'get_service',
        'get_service_application',
        'get_service_database',
        'get_deployment',
        'get_logs',
        'deploy',
        'control',
        'cancel_deployment',
        'list_application_previews',
        'list_env_keys',
        'list_resource_tags',
        'list_service_applications',
        'list_service_databases',
        'list_storages',
        'list_scheduled_tasks',
        'list_scheduled_task_executions',
        'list_database_backups',
        'list_backup_executions',
        'get_environment',
    ];

    /**
     * Tools that an environment-scoped token may call; they filter their results
     * to the token's environments inside the tool.
     *
     * @var array<int, string>
     */
    private const SCOPE_LIST_TOOLS = [
        'list_applications',
        'list_databases',
        'list_services',
        'list_resources',
        'list_deployments',
        'search_resources',
        'list_unhealthy_resources',
    ];

    protected function ensureAbility(Request $request, string $ability = 'read', ?string $tool = null): ?Response
    {
        $user = $request->user();
        if (! $user) {
            $this->auditMcpTool($request, $tool, 'denied', ['reason' => 'unauthenticated']);

            return Response::error('Unauthenticated.');
        }

        $token = $user->currentAccessToken();
        if (! $token) {
            $this->auditMcpTool($request, $tool, 'denied', ['reason' => 'invalid_token']);

            return Response::error('Invalid token.');
        }

        if ($error = $this->enforceEnvironmentScope($request, $tool)) {
            return $error;
        }

        $teamId = $token->team_id;
        if ($teamId !== null) {
            // Fresh pivot lookup (avoid stale $user->teams cache after role changes).
            $role = $user->teams()->where('teams.id', $teamId)->first()?->pivot?->role;
            $isAdminOrOwner = in_array($role, ['admin', 'owner'], true);

            if (! $isAdminOrOwner) {
                $tokenAbilities = $token->abilities ?? [];
                $disallowed = array_intersect($tokenAbilities, self::MEMBER_DISALLOWED_ABILITIES);
                if ($disallowed !== [] || in_array($ability, self::MEMBER_DISALLOWED_ABILITIES, true)) {
                    $this->auditMcpTool($request, $tool, 'denied', [
                        'reason' => 'member_role',
                        'required_ability' => $ability,
                    ]);

                    return Response::error('Missing required team role.');
                }
            }
        }

        if ($token->can('root') || $token->can($ability)) {
            return null;
        }

        $this->auditMcpTool($request, $tool, 'denied', [
            'reason' => 'missing_ability',
            'required_ability' => $ability,
        ]);

        return Response::error("Missing required permissions: {$ability}");
    }

    protected function resolveTeamId(Request $request): ?int
    {
        $user = $request->user();
        $token = $user?->currentAccessToken();
        $teamId = $token?->team_id;

        if (! $user || is_null($teamId) || ! $user->teams()->where('teams.id', $teamId)->exists()) {
            return null;
        }

        return (int) $teamId;
    }

    protected function mcpSuccess(Request $request, Response $response, array $context = []): Response
    {
        $this->auditMcpTool($request, $this->name ?? null, 'success', $context);

        return $response;
    }

    protected function mcpError(Request $request, string $message, array $context = []): Response
    {
        $this->auditMcpTool($request, $this->name ?? null, 'error', $context + ['reason' => $message]);

        return Response::error($message);
    }

    protected function auditMcpTool(Request $request, ?string $tool, string $outcome, array $context = []): void
    {
        auditLog('mcp.tool.called', [
            'tool' => $tool ?: 'unknown',
            'team_id' => $this->resolveTeamId($request),
            'outcome' => $outcome,
            ...$context,
        ]);
    }

    /**
     * Environment ids the current API token is restricted to, or null when the
     * token is unscoped (full team access) or there is no token.
     *
     * @return array<int, int>|null
     */
    protected function scopedEnvironmentIds(): ?array
    {
        return apiTokenScopedEnvironmentIds();
    }

    /**
     * Enforce the environment scope of the authenticated token for an MCP tool.
     *
     * Returns null when the request may continue, or an error Response when the
     * tool is team-level, targets an environment outside the scope, or cannot be
     * proven to be inside the scope (fail closed).
     */
    protected function enforceEnvironmentScope(Request $request, ?string $tool): ?Response
    {
        $scoped = $this->scopedEnvironmentIds();
        if ($scoped === null) {
            return null;
        }

        $tool ??= $this->name ?? null;
        if ($tool === null || $tool === 'coolify_help') {
            return $tool === 'coolify_help' ? null : $this->scopeDenied($request, $tool);
        }

        if (in_array($tool, self::SCOPE_LIST_TOOLS, true)) {
            return null;
        }

        if (in_array($tool, self::SCOPE_RESOURCE_TOOLS, true)) {
            $environmentId = $this->scopeTargetEnvironmentId($request, $tool);

            if (is_int($environmentId) && in_array($environmentId, $scoped, true)) {
                return null;
            }

            return $this->scopeDenied($request, $tool);
        }

        // Team-level tools (and any unclassified tool) are denied for scoped tokens.
        return $this->scopeDenied($request, $tool);
    }

    /**
     * Resolve the environment a resource-level tool targets, or null when it
     * cannot be resolved (which the caller treats as a denial).
     */
    protected function scopeTargetEnvironmentId(Request $request, string $tool): ?int
    {
        $teamId = $this->resolveTeamId($request);
        if (is_null($teamId)) {
            return null;
        }

        if ($tool === 'get_environment') {
            return $this->environmentIdFromProjectArgs($request, $teamId);
        }

        if ($tool === 'get_deployment' || $tool === 'cancel_deployment') {
            return $this->environmentIdFromDeployment($request);
        }

        if ($tool === 'list_backup_executions') {
            $databaseUuid = $request->get('database_uuid');

            return is_string($databaseUuid) && $databaseUuid !== ''
                ? $this->environmentIdFromResourceUuid($databaseUuid, $teamId)
                : null;
        }

        // Service children target the parent service's environment.
        $uuid = in_array($tool, ['get_service_application', 'get_service_database'], true)
            ? $request->get('service_uuid')
            : $request->get('uuid');

        if (! is_string($uuid) || $uuid === '') {
            return null;
        }

        return $this->environmentIdFromResourceUuid($uuid, $teamId);
    }

    private function environmentIdFromResourceUuid(string $uuid, int $teamId): ?int
    {
        $resource = getResourceByUuid($uuid, $teamId);
        if (! $resource) {
            return null;
        }

        $environmentId = data_get($resource, 'environment_id')
            ?? data_get($resource, 'service.environment_id');

        return is_null($environmentId) ? null : (int) $environmentId;
    }

    private function environmentIdFromDeployment(Request $request): ?int
    {
        $uuid = $request->get('uuid');
        if (! is_string($uuid) || $uuid === '') {
            return null;
        }

        $application = ApplicationDeploymentQueue::where('deployment_uuid', $uuid)->first()?->application;
        $environmentId = $application?->environment_id;

        return is_null($environmentId) ? null : (int) $environmentId;
    }

    private function environmentIdFromProjectArgs(Request $request, int $teamId): ?int
    {
        $projectUuid = $request->get('project_uuid');
        $environmentKey = $request->get('environment_name_or_uuid');

        if (! is_string($projectUuid) || $projectUuid === '' || ! is_string($environmentKey) || $environmentKey === '') {
            return null;
        }

        $project = Project::where('team_id', $teamId)->where('uuid', $projectUuid)->first();
        if (! $project) {
            return null;
        }

        $environment = Environment::where('project_id', $project->id)
            ->where(fn ($query) => $query->where('uuid', $environmentKey)->orWhere('name', $environmentKey))
            ->first();

        return $environment ? (int) $environment->id : null;
    }

    private function scopeDenied(Request $request, ?string $tool): Response
    {
        $this->auditMcpTool($request, $tool, 'denied', ['reason' => 'environment_scope']);

        return Response::error('This API token is restricted to specific environments and cannot access this resource.');
    }
}
