<?php

declare(strict_types=1);

namespace AuthKit\Token;

use RuntimeException;

final class InvalidToken extends RuntimeException
{
    public static function malformed(): self
    {
        return new self('Token is malformed.');
    }

    public static function badSignature(): self
    {
        return new self('Token signature does not match.');
    }

    public static function unsupportedAlgorithm(string $alg): self
    {
        return new self(sprintf('Token algorithm "%s" is not supported.', $alg));
    }

    public static function expired(): self
    {
        return new self('Token has expired.');
    }

    public static function notYetValid(): self
    {
        return new self('Token is not valid yet.');
    }
}
