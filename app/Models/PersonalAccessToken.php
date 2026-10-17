<?php

namespace App\Models;

use Laravel\Sanctum\PersonalAccessToken as SanctumPersonalAccessToken;

class PersonalAccessToken extends SanctumPersonalAccessToken
{
    protected $fillable = [
        'name',
        'token',
        'abilities',
        'expires_at',
        'api_token_expiration_warning_sent_at',
        'team_id',
        'scoped_environment_ids',
    ];

    protected function casts(): array
    {
        return [
            'api_token_expiration_warning_sent_at' => 'datetime',
            'scoped_environment_ids' => 'array',
        ];
    }

    /**
     * Whether the token is restricted to a fixed set of environments.
     * A null value keeps the token scoped to the whole team (legacy behaviour).
     */
    public function isEnvironmentScoped(): bool
    {
        return is_array($this->scoped_environment_ids);
    }

    /**
     * The environment ids the token is restricted to. Empty when the token is not scoped.
     *
     * @return array<int, int>
     */
    public function scopedEnvironmentIds(): array
    {
        if (! $this->isEnvironmentScoped()) {
            return [];
        }

        return array_values(array_map('intval', $this->scoped_environment_ids));
    }

    /**
     * Determine whether the token may act on the given environment.
     * Unscoped tokens keep access to every environment of their team.
     */
    public function allowsEnvironment(?int $environmentId): bool
    {
        if (! $this->isEnvironmentScoped()) {
            return true;
        }

        if (is_null($environmentId)) {
            return false;
        }

        return in_array((int) $environmentId, $this->scopedEnvironmentIds(), true);
    }
}
