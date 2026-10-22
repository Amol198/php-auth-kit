# php-auth-kit

Small, dependency-free authentication building blocks for PHP 8.2+.

The goal is a set of focused classes you can drop into a Laravel, Symfony or plain-PHP
service without pulling in a framework: signed tokens, login throttling and password
hashing, each behind a small interface and a deterministic `Clock` for testing.

## Status

| Component | State |
|---|---|
| `Support\Base64Url`, `Support\Clock` | done |
| HS256 token service (`Token\TokenService`) | done |
| Login rate limiter | in progress |
| Password hashing with transparent rehash | in progress |

## Requirements

- PHP 8.2 or newer
- Composer (dev only, for PHPUnit)

## Running the tests

```bash
composer install
composer test
```

## Tokens

```php
use AuthKit\Support\SystemClock;
use AuthKit\Token\TokenService;

$tokens = new TokenService(getenv('APP_TOKEN_SECRET'), new SystemClock());

$jwt    = $tokens->issue(['sub' => $user->id, 'scope' => 'read'], ttlSeconds: 900);
$claims = $tokens->verify($jwt); // throws AuthKit\Token\InvalidToken
```

## Design notes

- **No global time.** Everything that cares about "now" takes a `Clock`, so expiry and
  rate-limit windows are tested with `FrozenClock` instead of `sleep()`.
- **Strict types everywhere.** Every file declares `strict_types=1`.
- **Fail closed.** Anything that cannot be verified is treated as invalid.

## License

MIT
