<?php

use App\Enums\ApplicationDeploymentStatus;
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
use Illuminate\Support\Facades\Bus;

uses(RefreshDatabase::class);

beforeEach(function () {
    InstanceSettings::unguarded(fn () => InstanceSettings::query()->updateOrCreate(
        ['id' => 0],
        ['is_api_enabled' => true],
    ));

    $this->team = Team::factory()->create();
    $this->user = User::factory()->create();
    $this->team->members()->attach($this->user->id, ['role' => 'owner']);
    session(['currentTeam' => $this->team]);

    $this->server = Server::factory()->create(['team_id' => $this->team->id]);
    $this->destination = StandaloneDocker::query()->where('server_id', $this->server->id)->firstOrFail();

    $this->project = Project::factory()->create(['team_id' => $this->team->id]);
    $this->production = $this->project->environments()->first();
    $this->staging = Environment::factory()->create(['project_id' => $this->project->id, 'name' => 'staging']);

    $this->productionApp = scopeTestApplication($this->production, $this->destination);
    $this->stagingApp = scopeTestApplication($this->staging, $this->destination);

    $this->scopedToken = $this->user
        ->createToken('scoped', ['read', 'write', 'deploy'], null, [$this->production->id])
        ->plainTextToken;

    $this->unscopedToken = $this->user
        ->createToken('unscoped', ['read', 'write', 'deploy'])
        ->plainTextToken;
});

function scopeTestApplication(Environment $environment, StandaloneDocker $destination): Application
{
    return Application::factory()->create([
        'environment_id' => $environment->id,
        'destination_id' => $destination->id,
        'destination_type' => $destination->getMorphClass(),
        'git_repository' => 'https://github.com/coollabsio/coolify',
        'git_branch' => 'main',
        'git_commit_sha' => 'HEAD',
    ]);
}

function scopeTestHeaders(string $token): array
{
    return [
        'Authorization' => 'Bearer '.$token,
        'Content-Type' => 'application/json',
    ];
}

test('scoped token can read a resource inside its environment', function () {
    $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->getJson("/api/v1/applications/{$this->productionApp->uuid}")
        ->assertSuccessful();
});

test('scoped token is forbidden from a resource outside its environment', function () {
    $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->getJson("/api/v1/applications/{$this->stagingApp->uuid}")
        ->assertForbidden();
});

test('scoped token is forbidden from team level endpoints', function () {
    $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->getJson('/api/v1/servers')
        ->assertForbidden();
});

test('scoped token list only contains applications from its environment', function () {
    $response = $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->getJson('/api/v1/applications')
        ->assertSuccessful();

    $response->assertJsonCount(1)
        ->assertJsonFragment(['uuid' => $this->productionApp->uuid])
        ->assertJsonMissing(['uuid' => $this->stagingApp->uuid]);
});

test('scoped token cannot deploy a resource outside its environment', function () {
    Bus::fake();

    $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->postJson('/api/v1/deploy', ['uuid' => $this->stagingApp->uuid])
        ->assertForbidden();
});

test('scoped token cannot access project level endpoints', function () {
    $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->getJson("/api/v1/projects/{$this->project->uuid}")
        ->assertForbidden();
});

test('scoped token can read a deployment of a resource inside its environment', function () {
    $deployment = ApplicationDeploymentQueue::create([
        'deployment_uuid' => 'scope-prod-deployment',
        'application_id' => $this->productionApp->id,
        'status' => ApplicationDeploymentStatus::FINISHED->value,
    ]);

    $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->getJson("/api/v1/deployments/{$deployment->deployment_uuid}")
        ->assertSuccessful();
});

test('scoped token is forbidden from a deployment outside its environment', function () {
    $deployment = ApplicationDeploymentQueue::create([
        'deployment_uuid' => 'scope-staging-deployment',
        'application_id' => $this->stagingApp->id,
        'status' => ApplicationDeploymentStatus::FINISHED->value,
    ]);

    $this->withHeaders(scopeTestHeaders($this->scopedToken))
        ->getJson("/api/v1/deployments/{$deployment->deployment_uuid}")
        ->assertForbidden();
});

test('unscoped tokens keep access to every environment', function () {
    $this->withHeaders(scopeTestHeaders($this->unscopedToken))
        ->getJson("/api/v1/applications/{$this->stagingApp->uuid}")
        ->assertSuccessful();

    $this->withHeaders(scopeTestHeaders($this->unscopedToken))
        ->getJson('/api/v1/applications')
        ->assertSuccessful()
        ->assertJsonCount(2);
});

test('unscoped tokens keep access to team level endpoints', function () {
    $this->withHeaders(scopeTestHeaders($this->unscopedToken))
        ->getJson('/api/v1/servers')
        ->assertSuccessful();
});
