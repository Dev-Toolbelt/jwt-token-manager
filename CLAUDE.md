# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JWT Token Manager is a framework-agnostic PHP 8.1+ library for encoding, decoding, and validating JSON Web Tokens. It wraps `firebase/php-jwt` and adds session tracking, required claims validation, and a clean exception hierarchy.

## Commands

```bash
# Run all tests
composer test

# Run a single test file
./vendor/bin/phpunit tests/Unit/JwtTokenManagerTest.php

# Run a single test method
./vendor/bin/phpunit --filter testEncodeReturnsValidJwtToken

# Generate HTML coverage report (output: tests/coverage/)
composer test:coverage

# Check PSR-12 code style
composer phpcs

# Auto-fix code style issues
composer phpcs:fix

# Run static analysis (level 6)
composer phpstan
```

## Architecture

### Core Classes

- **JwtTokenManager** (`src/JwtTokenManager.php`) - Main class for `encode()`, `decode()`, and `generateRefreshToken()`. Generates UUID v7 for `jti` and `sid` claims automatically.

- **JwtConfig** (`src/JwtConfig.php`) - Immutable configuration object. Use factory methods `fromKeyFiles()` to load keys from disk or `fromArray()` for framework config arrays.

- **TokenPayload** (`src/TokenPayload.php`) - Immutable wrapper for decoded JWT claims with typed accessors.

- **Algorithm** (`DevToolbelt\Enums\Security\Algorithm` from `dev-toolbelt/jwt-token-manager`) - PHP 8.1 enum with 15 algorithms (HMAC, RSA, RSA-PSS, ECDSA, EdDSA). Has helper methods like `isSymmetric()` and `isAsymmetric()`.

- **Timezone** (`DevToolbelt\Enums\Locale\Timezone` from `dev-toolbelt/jwt-token-manager`) - PHP 8.1 enum with all PHP supported timezones. Default is UTC. Has helper methods `toDateTimeZone()`, `getUtcOffset()`, and `getUtcOffsetString()`.

### Exception Hierarchy

All exceptions extend `JwtException` (abstract base with error key support):

- `ExpiredTokenException` - Token past expiration
- `InvalidSignatureException` - Public key could not validate the token signature
- `InvalidTokenException` - Malformed token or not yet valid
- `InvalidClaimException` - Claim value mismatch (includes claim name, actual, expected values)
- `MissingClaimsException` - Required claims not present (includes array of missing claim names)

### Design Patterns

- All main classes are `final` with `readonly` properties (immutable)
- Protected claims (`iss`, `sub`, `iat`, `exp`, `jti`, `sid`) cannot be overridden by custom claims
- Factory pattern for configuration (`JwtConfig::fromKeyFiles()`, `JwtConfig::fromArray()`)
- 5-second clock skew tolerance for `nbf` claim

## Code Quality Standards

- PSR-12 with 120-char soft limit, 140-char hard limit
- Strict types declared on all files
- PHPStan level 6 for static analysis
- Test fixtures for RSA keys in `tests/fixtures/`
