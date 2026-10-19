<?php

declare(strict_types=1);

namespace AuthKit\Tests;

use AuthKit\Password\PasswordHasher;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    private PasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new PasswordHasher(bcryptCost: 4);
    }

    public function testHashIsNotThePlainPassword(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');

        self::assertNotSame('correct horse battery staple', $hash);
        self::assertStringStartsWith('$', $hash);
    }

    public function testCorrectPasswordVerifies(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');

        self::assertTrue($this->hasher->verify('correct horse battery staple', $hash)->valid);
    }

    public function testWrongPasswordIsRejected(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');

        $result = $this->hasher->verify('Tr0ub4dor&3', $hash);

        self::assertFalse($result->valid);
        self::assertFalse($result->needsPersisting());
    }

    public function testLegacyMd5HashVerifiesAndIsUpgraded(): void
    {
        $legacy = md5('letmein2019');

        $result = $this->hasher->verify('letmein2019', $legacy);

        self::assertTrue($result->valid);
        self::assertTrue($result->needsPersisting());
        self::assertTrue(password_verify('letmein2019', (string) $result->rehashed));
    }

    public function testLegacyMd5HashRejectsWrongPassword(): void
    {
        self::assertFalse($this->hasher->verify('nope', md5('letmein2019'))->valid);
    }

    public function testEmptyPasswordIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->hasher->hash('');
    }
}
