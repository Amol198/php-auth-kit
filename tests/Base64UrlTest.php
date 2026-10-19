<?php

declare(strict_types=1);

namespace AuthKit\Tests;

use AuthKit\Support\Base64Url;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function samples(): iterable
    {
        yield 'empty' => [''];
        yield 'one byte' => ['f'];
        yield 'two bytes' => ['fo'];
        yield 'three bytes' => ['foo'];
        yield 'binary' => [random_bytes(37)];
        yield 'json' => ['{"alg":"HS256","typ":"JWT"}'];
    }

    #[DataProvider('samples')]
    public function testRoundTrip(string $input): void
    {
        self::assertSame($input, Base64Url::decode(Base64Url::encode($input)));
    }

    public function testEncodingIsUrlSafeAndUnpadded(): void
    {
        $encoded = Base64Url::encode("\xfb\xff\xfe");

        self::assertSame('-__-', $encoded);
        self::assertStringNotContainsString('=', Base64Url::encode('f'));
    }

    public function testRejectsInvalidCharacters(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Base64Url::decode('abc+/=');
    }
}
