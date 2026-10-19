<?php

declare(strict_types=1);

namespace AuthKit\Token;

use AuthKit\Support\Base64Url;
use AuthKit\Support\Clock;
use InvalidArgumentException;
use JsonException;

/**
 * Issues and verifies compact JWTs signed with HMAC-SHA.
 *
 * Registered claims handled on verify:
 *  - exp: rejected once now > exp + leeway
 *  - nbf: rejected while now < nbf - leeway
 *  - iat: set automatically on issue
 */
final class TokenService
{
    /** @var array<string, string> JWT alg => hash_hmac algorithm */
    private const ALGORITHMS = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    public function __construct(
        private readonly string $secret,
        private readonly Clock $clock,
        private readonly string $algorithm = 'HS256',
        private readonly int $leewaySeconds = 30,
    ) {
        if (strlen($secret) < 32) {
            throw new InvalidArgumentException('Secret must be at least 32 bytes.');
        }
        if (!isset(self::ALGORITHMS[$algorithm])) {
            throw new InvalidArgumentException(sprintf('Unsupported algorithm "%s".', $algorithm));
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function issue(array $claims, int $ttlSeconds): string
    {
        $now = $this->clock->now();
        $claims['iat'] = $now;
        $claims['exp'] = $now + $ttlSeconds;

        $header = ['alg' => $this->algorithm, 'typ' => 'JWT'];

        $signingInput = Base64Url::encode($this->json($header))
            . '.'
            . Base64Url::encode($this->json($claims));

        return $signingInput . '.' . Base64Url::encode($this->sign($signingInput, self::ALGORITHMS[$this->algorithm]));
    }

    /**
     * @return array<string, mixed> the verified claims
     *
     * @throws InvalidToken
     */
    public function verify(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw InvalidToken::malformed();
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = $this->decodeSegment($encodedHeader);
        $claims = $this->decodeSegment($encodedPayload);

        $alg = (string) ($header['alg'] ?? '');
        $hashAlgo = self::ALGORITHMS[$alg] ?? null;
        if ($hashAlgo === null && $alg !== 'none') {
            throw InvalidToken::unsupportedAlgorithm($alg);
        }

        if ($hashAlgo !== null) {
            $expected = $this->sign($encodedHeader . '.' . $encodedPayload, $hashAlgo);
            if (Base64Url::encode($expected) !== $encodedSignature) {
                throw InvalidToken::badSignature();
            }
        }

        $now = $this->clock->now();
        if (isset($claims['exp']) && $now > (int) $claims['exp'] + $this->leewaySeconds) {
            throw InvalidToken::expired();
        }

        return $claims;
    }

    private function sign(string $input, string $hashAlgo): string
    {
        return hash_hmac($hashAlgo, $input, $this->secret, true);
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeSegment(string $segment): array
    {
        try {
            $decoded = json_decode(Base64Url::decode($segment), true, 32, JSON_THROW_ON_ERROR);
        } catch (InvalidArgumentException | JsonException) {
            throw InvalidToken::malformed();
        }

        if (!is_array($decoded)) {
            throw InvalidToken::malformed();
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function json(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
