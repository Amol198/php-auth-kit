<?php

declare(strict_types=1);

namespace AuthKit\Support;

/**
 * Test clock that only moves when told to.
 */
final class FrozenClock implements Clock
{
    public function __construct(private int $now)
    {
    }

    public function now(): int
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }
}
