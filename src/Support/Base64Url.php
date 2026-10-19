<?php

declare(strict_types=1);

namespace AuthKit\Support;

use InvalidArgumentException;

/**
 * URL-safe Base64 without padding (RFC 4648 §5), as used by JWT.
 */
final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        if (preg_match('/[^A-Za-z0-9\-_]/', $data) === 1) {
            throw new InvalidArgumentException('Input is not valid base64url.');
        }

        $padded = strtr($data, '-_', '+/');
        $remainder = strlen($padded) % 4;
        if ($remainder !== 0) {
            $padded .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new InvalidArgumentException('Input is not valid base64url.');
        }

        return $decoded;
    }
}
