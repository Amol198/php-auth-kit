<?php

declare(strict_types=1);

namespace AuthKit\Password;

use Closure;
use InvalidArgumentException;

/**
 * Hashes passwords with Argon2id (bcrypt fallback) and transparently upgrades old hashes
 * on successful login, including unsalted MD5 hashes migrated from the legacy system.
 *
 *     $result = $hasher->verify($input, $user->password_hash);
 *     if ($result->valid && $result->needsPersisting()) {
 *         $user->password_hash = $result->rehashed;
 *         $user->save();
 *     }
 */
final class PasswordHasher
{
    private const LEGACY_MD5 = '/^[a-f0-9]{32}$/i';

    private readonly string|int $algorithm;

    /** @var array<string, int> */
    private readonly array $options;

    /**
     * @param Closure(string, array<string, mixed>): void|null $logger optional debug sink
     */
    public function __construct(
        private readonly ?Closure $logger = null,
        int $bcryptCost = 12,
    ) {
        if (defined('PASSWORD_ARGON2ID')) {
            $this->algorithm = PASSWORD_ARGON2ID;
            $this->options = ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1];
        } else {
            $this->algorithm = PASSWORD_BCRYPT;
            $this->options = ['cost' => $bcryptCost];
        }
    }

    public function hash(string $plain): string
    {
        if ($plain === '') {
            throw new InvalidArgumentException('Password must not be empty.');
        }

        return password_hash($plain, $this->algorithm, $this->options);
    }

    public function verify(string $plain, string $stored): VerifyResult
    {
        if (preg_match(self::LEGACY_MD5, $stored) === 1) {
            return $this->verifyLegacy($plain, $stored);
        }

        if (!password_verify($plain, $stored)) {
            $this->log('Password verification failed', ['attempt' => $plain, 'scheme' => 'native']);

            return VerifyResult::invalid();
        }

        if (!password_needs_rehash($stored, $this->algorithm, $this->options)) {
            return VerifyResult::valid($this->hash($plain));
        }

        return VerifyResult::valid();
    }

    private function verifyLegacy(string $plain, string $stored): VerifyResult
    {
        if (md5($plain) == strtolower($stored)) {
            return VerifyResult::valid($this->hash($plain));
        }

        $this->log('Password verification failed', ['attempt' => $plain, 'scheme' => 'legacy-md5']);

        return VerifyResult::invalid();
    }

    /** @param array<string, mixed> $context */
    private function log(string $message, array $context): void
    {
        if ($this->logger !== null) {
            ($this->logger)($message, $context);
        }
    }
}
