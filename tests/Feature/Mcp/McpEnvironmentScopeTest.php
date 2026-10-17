<?php

use App\Models\Application;
use App\Models\ApplicationDeploymentQueue;
use App\Models\Environment;
use App\Models\InstanceSettings;
use App\Models\Project;
use App\Models\Server;
use App\Models\StandaloneDocker;
use App\Models\Team;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function () {
    config([
        'cache.default' => 'array',
        'session.driver' => 'array',
        'queue.default' => 'sync',
        'app.maintenance.driver' => 'file',
    ]);

    InstanceSettings::query()->delete();
    $settings = new InstanceSettings(['is_mcp_server_enabled' => true]);
    $settings->id = 0;
    $settings->save();

    $this->team = Team::factory()->create();
    $this->user = User::factory()->create();
    $this->team->members()->attach($this->user->id, ['role' => 'owner']);
    session(['currentTeam' => $this->team]);

    $this->server = Server::factory()->create(['team_id' => $this->team->id]);
    $this->destination = StandaloneDocker::query()->where('server_id', $this->server->id)->firstOrFail();

    $this->project = Project::factory()->create(['team_id' => $this->team->id]);
    $this->production = $this->project->environments()->first();
    $this->staging = Environment::factory()->create(['project_id' => $this->project->id, 'name' => 'staging']);

    $this->productionApp = mcpScopeApplication($this->production, $this->destination);
    $this->stagingApp = mcpScopeApplication($this->staging, $this->destination);
});

function mcpScopeApplication(Environment $environment, StandaloneDocker $destination): Application
{
    return Application::factory()->create([
        'environment_id' => $environment->id,
        'destination_id' => $destination->id,
        'destination_type' => $destination->getMorphClass(),
        'fqdn' => 'https://'.str()->random(8).'.example.com',
    ]);
}

function mcpScopedToken(array $scopedEnvironmentIds = [], array $abilities = ['read']): string
{
    return test()->user->createToken('mcp-scoped', $abilities, null, $scopedEnvironmentIds)->plainTextToken;
}

function mcpUnscopedToken(array $abilities = ['read']): string
{
    return test()->user->createToken('mcp-unscoped', $abilities)->plainTextToken;
}

function mcpScopeCall(string $token, string $name, array $arguments = [])
{
    auth()->forgetGuards();

    return test()->withHeaders([
        'Content-Type' => 'application/json',
        'Accept' => 'application/json, text/event-stream',
        'Authorization' => 'Bearer '.$token,
    ])->postJson('/mcp', [
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'tools/call',
        'params' => [
            'name' => $name,
            'arguments' => (object) $arguments,
        ],
    ]);
}

/**
 * @return array<string, mixed>
 */
function mcpScopeJson($response): array
{
    return json_decode($response->json('result.content.0.text'), true) ?? [];
}

test('scoped token can read a resource inside its environment', function () {
    $token = mcpScopedToken([$this->production->id]);

    $response = mcpScopeCall($token, 'get_application', ['uuid' => $this->productionApp->uuid]);

    expect($response->json('result.isError'))->toBeFalse();
    expect(mcpScopeJson($response)['data']['uuid'])->toBe($this->productionApp->uuid);
});

test('scoped token is forbidden from a resource outside its environment', function () {
    $token = mcpScopedToken([$this->production->id]);

    $response = mcpScopeCall($token, 'get_application', ['uuid' => $this->stagingApp->uuid]);

    expect($response->json('result.isError'))->toBeTrue();
    expect($response->json('result.content.0.text'))->toContain('restricted to specific environments');
});

test('scoped token list only contains applications from its environment', function () {
    $token = mcpScopedToken([$this->production->id]);

    $response = mcpScopeCall($token, 'list_applications');

    expect($response->json('result.isError'))->toBeFalse();
    $data = mcpScopeJson($response)['data'];
    expect(collect($data)->pluck('uuid')->all())->toBe([$this->productionApp->uuid]);
});

test('scoped token list_resources only contains resources from its environment', function () {
    $token = mcpScopedToken([$this->production->id]);

    $response = mcpScopeCall($token, 'list_resources');

    expect($response->json('result.isError'))->toBeFalse();
    $uuids = collect(mcpScopeJson($response)['data'])->pluck('uuid')->all();
    expect($uuids)->toContain($this->productionApp->uuid)
        ->and($uuids)->not->toContain($this->stagingApp->uuid);
});

test('scoped token is forbidden from team level tools', function () {
    $token = mcpScopedToken([$this->production->id]);

    expect(mcpScopeCall($token, 'list_servers')->json('result.isError'))->toBeTrue();
    expect(mcpScopeCall($token, 'get_current_team')->json('result.isError'))->toBeTrue();
    expect(mcpScopeCall($token, 'list_projects')->json('result.isError'))->toBeTrue();
});

test('scoped token list_deployments only contains deployments from its environment', function () {
    ApplicationDeploymentQueue::create([
        'deployment_uuid' => 'scope-prod',
        'application_id' => $this->productionApp->id,
        'status' => 'finished',
    ]);
    ApplicationDeploymentQueue::create([
        'deployment_uuid' => 'scope-staging',
        'application_id' => $this->stagingApp->id,
        'status' => 'finished',
    ]);

    $token = mcpScopedToken([$this->production->id]);
    $response = mcpScopeCall($token, 'list_deployments', ['status' => 'all']);

    expect($response->json('result.isError'))->toBeFalse();
    $uuids = collect(mcpScopeJson($response)['data'])->pluck('deployment_uuid')->all();
    expect($uuids)->toContain('scope-prod')->and($uuids)->not->toContain('scope-staging');
});

test('scoped token search_resources excludes other environments and team level types', function () {
    $token = mcpScopedToken([$this->production->id]);

    $response = mcpScopeCall($token, 'search_resources', ['query' => 'https://', 'types' => 'application,server,project']);

    expect($response->json('result.isError'))->toBeFalse();
    $results = mcpScopeJson($response)['data']['results'] ?? [];
    $uuids = collect($results)->pluck('uuid')->all();
    $types = collect($results)->pluck('type')->unique()->all();

    expect($uuids)->toContain($this->productionApp->uuid)
        ->and($uuids)->not->toContain($this->stagingApp->uuid)
        ->and($types)->not->toContain('server')
        ->and($types)->not->toContain('project');
});

test('scoped token cannot deploy a resource outside its environment', function () {
    $token = mcpScopedToken([$this->production->id], ['read', 'deploy']);

    $response = mcpScopeCall($token, 'deploy', ['uuid' => $this->stagingApp->uuid]);

    expect($response->json('result.isError'))->toBeTrue();
    expect($response->json('result.content.0.text'))->toContain('restricted to specific environments');
});

test('unscoped tokens keep full access to team level tools', function () {
    $token = mcpUnscopedToken();

    expect(mcpScopeCall($token, 'list_servers')->json('result.isError'))->toBeFalse();
    expect(mcpScopeCall($token, 'list_applications')->json('result.isError'))->toBeFalse();
});
