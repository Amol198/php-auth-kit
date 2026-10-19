<?php

declare(strict_types=1);

namespace AuthKit\RateLimit;

use AuthKit\Support\Clock;

/**
 * Process-local store. Suitable for tests and single-worker CLI tools only.
 */
final class InMemoryStore implements Store
{
    /** @var array<string, array{value: array{attempts: int, resetAt: int}, expiresAt: int}> */
    private array $items = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    public function get(string $key): ?array
    {
        $item = $this->items[$key] ?? null;
        if ($item === null) {
            return null;
        }

        if ($item['expiresAt'] <= $this->clock->now()) {
            unset($this->items[$key]);

            return null;
        }

        return $item['value'];
    }

    public function put(string $key, array $value, int $expiresAt): void
    {
        $this->items[$key] = ['value' => $value, 'expiresAt' => $expiresAt];
    }

    public function forget(string $key): void
    {
        unset($this->items[$key]);
    }
}
