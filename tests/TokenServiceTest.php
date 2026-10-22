<?php

declare(strict_types=1);

namespace AuthKit\Tests;

use AuthKit\Support\FrozenClock;
use AuthKit\Token\InvalidToken;
use AuthKit\Token\TokenService;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class TokenServiceTest extends TestCase
{
    private const SECRET = 'test-secret-that-is-at-least-32-bytes-long';

    private FrozenClock $clock;
    private TokenService $tokens;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock(1_800_000_000);
        $this->tokens = new TokenService(self::SECRET, $this->clock, 'HS256', 30);
    }

    public function testIssuedTokenVerifiesAndReturnsClaims(): void
    {
        $token = $this->tokens->issue(['sub' => 'user-42', 'scope' => 'read'], 300);

        $claims = $this->tokens->verify($token);

        self::assertSame('user-42', $claims['sub']);
        self::assertSame('read', $claims['scope']);
        self::assertSame(1_800_000_000, $claims['iat']);
        self::assertSame(1_800_000_300, $claims['exp']);
    }

    public function testTokenIsAcceptedWithinLeewayAfterExpiry(): void
    {
        $token = $this->tokens->issue(['sub' => 'user-42'], 60);
        $this->clock->advance(60 + 30);

        self::assertSame('user-42', $this->tokens->verify($token)['sub']);
    }

    public function testExpiredTokenIsRejected(): void
    {
        $token = $this->tokens->issue(['sub' => 'user-42'], 60);
        $this->clock->advance(60 + 31);

        $this->expectException(InvalidToken::class);
        $this->expectExceptionMessage('expired');

        $this->tokens->verify($token);
    }

    public function testTamperedPayloadIsRejected(): void
    {
        $token = $this->tokens->issue(['sub' => 'user-42', 'role' => 'user'], 300);
        [$header, , $signature] = explode('.', $token);
        $forgedPayload = rtrim(strtr(base64_encode('{"sub":"user-42","role":"admin"}'), '+/', '-_'), '=');

        $this->expectException(InvalidToken::class);

        $this->tokens->verify($header . '.' . $forgedPayload . '.' . $signature);
    }

    public function testTokenSignedWithAnotherSecretIsRejected(): void
    {
        $other = new TokenService(str_repeat('x', 40), $this->clock);
        $token = $other->issue(['sub' => 'user-42'], 300);

        $this->expectException(InvalidToken::class);

        $this->tokens->verify($token);
    }

    public function testUnsignedAlgNoneTokenIsRejected(): void
    {
        $encode = static fn (string $json): string => rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $token = $encode('{"alg":"none","typ":"JWT"}') . '.' . $encode('{"sub":"admin"}') . '.';

        $this->expectException(InvalidToken::class);
        $this->expectExceptionMessage('algorithm');

        $this->tokens->verify($token);
    }

    public function testTokenWithDifferentHmacAlgorithmIsRejected(): void
    {
        $other = new TokenService(self::SECRET, $this->clock, 'HS512');
        $token = $other->issue(['sub' => 'user-42'], 300);

        $this->expectException(InvalidToken::class);
        $this->expectExceptionMessage('algorithm');

        $this->tokens->verify($token);
    }

    public function testMalformedTokenIsRejected(): void
    {
        $this->expectException(InvalidToken::class);

        $this->tokens->verify('not-a-jwt');
    }

    public function testShortSecretIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TokenService('too-short', $this->clock);
    }
}
