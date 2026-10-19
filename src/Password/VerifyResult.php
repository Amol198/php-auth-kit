<?php

declare(strict_types=1);

namespace AuthKit\Password;

/**
 * Outcome of a password check. When $rehashed is non-null the caller should persist it
 * in place of the stored hash.
 */
final class VerifyResult
{
    private function __construct(
        public readonly bool $valid,
        public readonly ?string $rehashed,
    ) {
    }

    public static function invalid(): self
    {
        return new self(false, null);
    }

    public static function valid(?string $rehashed = null): self
    {
        return new self(true, $rehashed);
    }

    public function needsPersisting(): bool
    {
        return $this->rehashed !== null;
    }
}
