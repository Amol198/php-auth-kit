<?php

declare(strict_types=1);

namespace AuthKit\Tests;

use AuthKit\RateLimit\InMemoryStore;
use AuthKit\RateLimit\LoginThrottle;
use AuthKit\Support\FrozenClock;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class LoginThrottleTest extends TestCase
{
    private const EMAIL = 'amol@example.com';
    private const IP = '203.0.113.7';

    private FrozenClock $clock;
    private LoginThrottle $throttle;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock(1_800_000_000);
        $this->throttle = new LoginThrottle(new InMemoryStore($this->clock), $this->clock, maxAttempts: 5, decaySeconds: 600);
    }

    public function testFreshIdentifierIsNotThrottled(): void
    {
        self::assertFalse($this->throttle->tooManyAttempts(self::EMAIL, self::IP));
        self::assertSame(0, $this->throttle->availableIn(self::EMAIL, self::IP));
    }

    public function testHitReturnsRunningCount(): void
    {
        self::assertSame(1, $this->throttle->hit(self::EMAIL, self::IP));
        self::assertSame(2, $this->throttle->hit(self::EMAIL, self::IP));
        self::assertSame(2, $this->throttle->attempts(self::EMAIL, self::IP));
    }

    public function testRepeatedFailuresAreThrottled(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->throttle->hit(self::EMAIL, self::IP);
        }

        self::assertTrue($this->throttle->tooManyAttempts(self::EMAIL, self::IP));
        self::assertSame(600, $this->throttle->availableIn(self::EMAIL, self::IP));
    }

    public function testThrottleLiftsAfterTheWindow(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->throttle->hit(self::EMAIL, self::IP);
        }

        $this->clock->advance(601);

        self::assertFalse($this->throttle->tooManyAttempts(self::EMAIL, self::IP));
        self::assertSame(0, $this->throttle->attempts(self::EMAIL, self::IP));
    }

    public function testClearResetsAfterSuccessfulLogin(): void
    {
        $this->throttle->hit(self::EMAIL, self::IP);
        $this->throttle->hit(self::EMAIL, self::IP);

        $this->throttle->clear(self::EMAIL, self::IP);

        self::assertSame(0, $this->throttle->attempts(self::EMAIL, self::IP));
    }

    public function testDifferentIpsAreTrackedSeparately(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->throttle->hit(self::EMAIL, self::IP);
        }

        self::assertFalse($this->throttle->tooManyAttempts(self::EMAIL, '198.51.100.20'));
    }

    public function testRejectsNonPositiveLimits(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new LoginThrottle(new InMemoryStore($this->clock), $this->clock, maxAttempts: 0);
    }
}
