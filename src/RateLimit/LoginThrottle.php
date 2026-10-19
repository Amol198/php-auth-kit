<?php

declare(strict_types=1);

namespace AuthKit\RateLimit;

use AuthKit\Support\Clock;
use InvalidArgumentException;

/**
 * Fixed-window throttle for failed login attempts, keyed by account identifier and client IP.
 *
 * Typical flow:
 *
 *     if ($throttle->tooManyAttempts($email, $ip)) {
 *         return retryLater($throttle->availableIn($email, $ip));
 *     }
 *     if (!$auth->attempt($email, $password)) {
 *         $throttle->hit($email, $ip);
 *         return invalidCredentials();
 *     }
 *     $throttle->clear($email, $ip);
 *
 * The window opens on the first failed attempt and closes $decaySeconds later,
 * regardless of how many attempts happen inside it.
 */
final class LoginThrottle
{
    public function __construct(
        private readonly Store $store,
        private readonly Clock $clock,
        private readonly int $maxAttempts = 5,
        private readonly int $decaySeconds = 900,
    ) {
        if ($maxAttempts < 1 || $decaySeconds < 1) {
            throw new InvalidArgumentException('maxAttempts and decaySeconds must be positive.');
        }
    }

    public function tooManyAttempts(string $identifier, string $ip): bool
    {
        return $this->attempts($identifier, $ip) > $this->maxAttempts;
    }

    /** Records one failed attempt and returns the attempt count inside the current window. */
    public function hit(string $identifier, string $ip): int
    {
        $key = $this->key($identifier, $ip);
        $now = $this->clock->now();

        $record = $this->store->get($key);
        $attempts = ($record['attempts'] ?? 0) + 1;
        $resetAt = $now + $this->decaySeconds;

        $this->store->put($key, ['attempts' => $attempts, 'resetAt' => $resetAt], $resetAt);

        return $attempts;
    }

    public function attempts(string $identifier, string $ip): int
    {
        return $this->store->get($this->key($identifier, $ip))['attempts'] ?? 0;
    }

    /** Seconds until the caller may try again; 0 when not throttled. */
    public function availableIn(string $identifier, string $ip): int
    {
        $record = $this->store->get($this->key($identifier, $ip));
        if ($record === null) {
            return 0;
        }

        return max(0, $record['resetAt'] - $this->clock->now());
    }

    public function clear(string $identifier, string $ip): void
    {
        $this->store->forget($this->key($identifier, $ip));
    }

    private function key(string $identifier, string $ip): string
    {
        return 'login:' . sha1($identifier . '|' . $ip);
    }
}
