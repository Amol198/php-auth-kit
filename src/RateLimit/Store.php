<?php

declare(strict_types=1);

namespace AuthKit\RateLimit;

/**
 * Minimal key/value store for throttle state.
 *
 * Implementations are expected to drop an entry once its expiry timestamp has passed.
 * A Redis or database implementation can be swapped in for multi-node deployments.
 */
interface Store
{
    /** @return array{attempts: int, resetAt: int}|null */
    public function get(string $key): ?array;

    /** @param array{attempts: int, resetAt: int} $value */
    public function put(string $key, array $value, int $expiresAt): void;

    public function forget(string $key): void;
}
