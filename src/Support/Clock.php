<?php

declare(strict_types=1);

namespace AuthKit\Support;

/**
 * Time source abstraction so expiry and window logic can be tested deterministically.
 */
interface Clock
{
    /** Current Unix timestamp in seconds. */
    public function now(): int;
}
