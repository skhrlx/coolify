<?php

namespace App\Livewire\Security;

use App\Models\Environment;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Validation\Rule;
use Laravel\Sanctum\PersonalAccessToken;
use Livewire\Attributes\Locked;
use Livewire\Component;

class ApiTokens extends Component
{
    use AuthorizesRequests;

    public ?string $description = null;

    /**
     * Untyped on purpose: Livewire skips hydrating null into typed properties, which
     * would silently revert a "Never" (null) choice back to the default on the next request.
     *
     * @var int|string|null
     */
    public $expiresInDays = 30;

    public $tokens = [];

    public array $permissions = ['read'];

    /**
     * When true, the new token is restricted to the selected environments.
     */
    public bool $restrictToEnvironments = false;

    /**
     * @var array<int, int|string>
     */
    public array $selectedEnvironmentIds = [];

    /**
     * Environments of the current team grouped by project, for the scope picker.
     *
     * @var array<string, array<int, array{id: string, name: string, uuid: string}>>
     */
    public array $environmentGroups = [];

    /**
     * Environment id => "Project / environment" label, for the token table.
     *
     * @var array<int, string>
     */
    public array $environmentNames = [];

    public array $expirationOptions = [
        7 => '7 days',
        30 => '30 days',
        60 => '60 days',
        90 => '90 days',
        365 => '1 year',
    ];

    #[Locked]
    public bool $canUseRootPermissions = false;

    #[Locked]
    public bool $canUseWritePermissions = false;

    #[Locked]
    public bool $canUseDeployPermissions = false;

    #[Locked]
    public bool $canUseSensitivePermissions = false;

    public function render()
    {
        return view('livewire.security.api-tokens');
    }

    public function mount()
    {
        $this->canUseRootPermissions = auth()->user()->can('useRootPermissions', PersonalAccessToken::class);
        $this->canUseWritePermissions = auth()->user()->can('useWritePermissions', PersonalAccessToken::class);
        $this->canUseDeployPermissions = auth()->user()->can('useDeployPermissions', PersonalAccessToken::class);
        $this->canUseSensitivePermissions = auth()->user()->can('useSensitivePermissions', PersonalAccessToken::class);
        $this->loadEnvironments();
        $this->getTokens();
    }

    private function loadEnvironments(): void
    {
        $environments = Environment::ownedByCurrentTeam()
            ->with('project:id,name')
            ->get();

        $this->environmentGroups = $environments
            ->groupBy(fn ($environment) => $environment->project?->name ?? 'Unassigned')
            ->map(fn ($group) => $group->map(fn ($environment) => [
                'id' => (string) $environment->id,
                'name' => $environment->name,
                'uuid' => $environment->uuid,
            ])->values()->all())
            ->all();

        $this->environmentNames = $environments
            ->mapWithKeys(fn ($environment) => [
                (int) $environment->id => trim(($environment->project?->name ?? 'Unassigned').' / '.$environment->name),
            ])
            ->all();
    }

    private function getTokens()
    {
        $this->tokens = auth()->user()->tokens()
            ->where('team_id', currentTeam()->id)
            ->latest()
            ->get();
    }

    public function updatedPermissions($permissionToUpdate)
    {
        // Re-evaluate policies fresh — never trust stored snapshot booleans.
        if ($permissionToUpdate == 'root' && ! auth()->user()->can('useRootPermissions', PersonalAccessToken::class)) {
            $this->dispatch('error', 'You do not have permission to use root permissions.');
            $this->permissions = array_diff($this->permissions, ['root']);

            return;
        }

        if (in_array($permissionToUpdate, ['write', 'write:sensitive'], true) && ! auth()->user()->can('useWritePermissions', PersonalAccessToken::class)) {
            $this->dispatch('error', 'You do not have permission to use write permissions.');
            $this->permissions = array_diff($this->permissions, ['write', 'write:sensitive']);

            return;
        }

        if ($permissionToUpdate == 'deploy' && ! auth()->user()->can('useDeployPermissions', PersonalAccessToken::class)) {
            $this->dispatch('error', 'You do not have permission to use deploy permissions.');
            $this->permissions = array_diff($this->permissions, ['deploy']);

            return;
        }

        if ($permissionToUpdate == 'read:sensitive' && ! auth()->user()->can('useSensitivePermissions', PersonalAccessToken::class)) {
            $this->dispatch('error', 'You do not have permission to use read:sensitive permissions.');
            $this->permissions = array_diff($this->permissions, ['read:sensitive']);

            return;
        }

        if ($permissionToUpdate == 'root' && in_array('root', $this->permissions, true)) {
            $this->permissions = ['root'];
        } elseif ($permissionToUpdate == 'read:sensitive' && ! in_array('read', $this->permissions, true)) {
            $this->permissions[] = 'read';
        } elseif ($permissionToUpdate == 'deploy' && in_array('deploy', $this->permissions, true)) {
            $this->permissions = ['deploy'];
        } else {
            if (count($this->permissions) == 0) {
                $this->permissions = ['read'];
            }
        }
        sort($this->permissions);
    }

    /**
     * Normalise and validate the environment scope selection against the current team.
     * Returns null for an unrestricted token.
     *
     * @return array<int, int>|null
     */
    private function resolveScopedEnvironmentIds(): ?array
    {
        if (! $this->restrictToEnvironments) {
            return null;
        }

        $submitted = collect($this->selectedEnvironmentIds)
            ->map(fn ($id) => (int) $id)
            ->unique()
            ->values();

        if ($submitted->isEmpty()) {
            throw new \Exception('Select at least one environment to restrict this token.');
        }

        // Re-resolve from the current team so a tampered Livewire snapshot cannot
        // attach environments that belong to another team.
        $allowed = Environment::ownedByCurrentTeam()
            ->whereIn('id', $submitted->all())
            ->pluck('id')
            ->map(fn ($id) => (int) $id)
            ->unique()
            ->values();

        if ($allowed->count() !== $submitted->count()) {
            throw new \Exception('One or more selected environments do not belong to the current team.');
        }

        return $allowed->all();
    }

    public function addNewToken()
    {
        try {
            $this->authorize('create', PersonalAccessToken::class);

            $validated = $this->validate([
                'description' => 'required|min:3|max:255',
                'expiresInDays' => 'nullable|integer|in:7,30,60,90,365',
                'permissions' => 'required|array|min:1',
                'permissions.*' => ['required', 'string', Rule::in(['read', 'read:sensitive', 'write', 'write:sensitive', 'deploy', 'root'])],
                'restrictToEnvironments' => 'boolean',
                'selectedEnvironmentIds' => 'array',
                'selectedEnvironmentIds.*' => 'integer',
            ]);
            $permissions = array_values($validated['permissions']);
            $scopedEnvironmentIds = $this->resolveScopedEnvironmentIds();

            // Re-evaluate policies fresh against the current authenticated user.
            // Never trust $this->canUse* booleans — they come from the Livewire
            // snapshot which can be replayed from another user's session.
            if (in_array('root', $permissions, true) && ! auth()->user()->can('useRootPermissions', PersonalAccessToken::class)) {
                throw new \Exception('You do not have permission to create tokens with root permissions.');
            }

            if (array_intersect(['write', 'write:sensitive'], $permissions) && ! auth()->user()->can('useWritePermissions', PersonalAccessToken::class)) {
                throw new \Exception('You do not have permission to create tokens with write permissions.');
            }

            if (in_array('deploy', $permissions, true) && ! auth()->user()->can('useDeployPermissions', PersonalAccessToken::class)) {
                throw new \Exception('You do not have permission to create tokens with deploy permissions.');
            }

            if (in_array('read:sensitive', $permissions, true) && ! auth()->user()->can('useSensitivePermissions', PersonalAccessToken::class)) {
                throw new \Exception('You do not have permission to create tokens with read:sensitive permissions.');
            }

            $expiresAt = filled($validated['expiresInDays'] ?? null) ? now()->addDays((int) $validated['expiresInDays']) : null;
            $token = auth()->user()->createToken($this->description, $permissions, $expiresAt, $scopedEnvironmentIds);
            auditLog('ui.api_token.created', [
                'team_id' => currentTeam()->id,
                'api_token_name' => $this->description,
                'abilities' => $permissions,
                'scoped_environment_ids' => $scopedEnvironmentIds,
                'expires_at' => $expiresAt?->toIso8601String(),
            ]);
            $this->restrictToEnvironments = false;
            $this->selectedEnvironmentIds = [];
            $this->getTokens();
            // Do NOT strip the numeric prefix (e.g. "69|...") — Sanctum uses it to index and look up tokens.
            session()->flash('token', $token->plainTextToken);
        } catch (\Exception $e) {
            return handleError($e, $this);
        }
    }

    public function revoke(int $id)
    {
        try {
            $token = auth()->user()->tokens()
                ->where('team_id', currentTeam()->id)
                ->where('id', $id)
                ->firstOrFail();
            $this->authorize('delete', $token);
            $tokenName = $token->name;
            $token->delete();
            auditLog('ui.api_token.revoked', [
                'team_id' => currentTeam()->id,
                'api_token_name' => $tokenName,
            ]);
            $this->getTokens();
        } catch (\Exception $e) {
            return handleError($e, $this);
        }
    }
}
