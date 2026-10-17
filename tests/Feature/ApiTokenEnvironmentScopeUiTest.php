<?php

use App\Livewire\Security\ApiTokens;
use App\Models\InstanceSettings;
use App\Models\Project;
use App\Models\Team;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\Livewire;

uses(RefreshDatabase::class);

beforeEach(function () {
    InstanceSettings::forceCreate(['id' => 0, 'is_api_enabled' => true]);

    $this->team = Team::factory()->create();
    $this->owner = User::factory()->create();
    $this->team->members()->attach($this->owner->id, ['role' => 'owner']);

    $this->actingAs($this->owner);
    session(['currentTeam' => $this->team]);

    $this->project = Project::factory()->create(['team_id' => $this->team->id]);
    $this->environment = $this->project->environments()->first();
});

test('owner can create a token restricted to an environment', function () {
    Livewire::test(ApiTokens::class)
        ->set('description', 'scoped-token')
        ->set('expiresInDays', 30)
        ->set('permissions', ['read'])
        ->set('restrictToEnvironments', true)
        ->set('selectedEnvironmentIds', [(string) $this->environment->id])
        ->call('addNewToken')
        ->assertHasNoErrors();

    $token = $this->owner->tokens()->latest()->first();

    expect($token)->not->toBeNull()
        ->and($token->isEnvironmentScoped())->toBeTrue()
        ->and($token->scopedEnvironmentIds())->toBe([$this->environment->id]);
});

test('restricted tokens require at least one environment', function () {
    Livewire::test(ApiTokens::class)
        ->set('description', 'scoped-token')
        ->set('expiresInDays', 30)
        ->set('permissions', ['read'])
        ->set('restrictToEnvironments', true)
        ->set('selectedEnvironmentIds', [])
        ->call('addNewToken');

    expect($this->owner->tokens()->count())->toBe(0);
});

test('cannot restrict a token to an environment from another team', function () {
    $otherTeam = Team::factory()->create();
    $otherProject = Project::factory()->create(['team_id' => $otherTeam->id]);
    $otherEnvironment = $otherProject->environments()->first();

    Livewire::test(ApiTokens::class)
        ->set('description', 'scoped-token')
        ->set('expiresInDays', 30)
        ->set('permissions', ['read'])
        ->set('restrictToEnvironments', true)
        ->set('selectedEnvironmentIds', [(string) $otherEnvironment->id])
        ->call('addNewToken');

    expect($this->owner->tokens()->count())->toBe(0);
});

test('unscoped tokens are stored without a scope', function () {
    Livewire::test(ApiTokens::class)
        ->set('description', 'unscoped-token')
        ->set('expiresInDays', 30)
        ->set('permissions', ['read'])
        ->call('addNewToken')
        ->assertHasNoErrors();

    $token = $this->owner->tokens()->latest()->first();

    expect($token)->not->toBeNull()
        ->and($token->isEnvironmentScoped())->toBeFalse()
        ->and($token->scoped_environment_ids)->toBeNull();
});
