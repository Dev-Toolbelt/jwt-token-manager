# JWT Token Manager

[![CI](https://github.com/dev-toolbelt/jwt-token-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/dev-toolbelt/jwt-token-manager/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/dev-toolbelt/jwt-token-manager/branch/main/graph/badge.svg)](https://codecov.io/gh/dev-toolbelt/jwt-token-manager)
[![Latest Stable Version](https://poser.pugx.org/dev-toolbelt/jwt-token-manager/v/stable)](https://packagist.org/packages/dev-toolbelt/jwt-token-manager)
[![Total Downloads](https://poser.pugx.org/dev-toolbelt/jwt-token-manager/downloads)](https://packagist.org/packages/dev-toolbelt/jwt-token-manager)
[![License](https://poser.pugx.org/dev-toolbelt/jwt-token-manager/license)](https://packagist.org/packages/dev-toolbelt/jwt-token-manager)
[![PHP Version](https://img.shields.io/packagist/php-v/dev-toolbelt/jwt-token-manager)](https://packagist.org/packages/dev-toolbelt/jwt-token-manager)

A **framework-agnostic** PHP library for encoding, decoding, and validating JSON Web Tokens (JWT) with support for RSA, HMAC, ECDSA, and EdDSA algorithms.

Built with simplicity and security in mind, this package provides an easy way to manage JWT tokens without coupling your application to any specific framework.

## Features

- **Framework Agnostic** - Use with Laravel, Symfony, Yii, Slim, or any PHP application
- **Multiple Algorithms** - Support for HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, and EdDSA
- **Type-Safe Configuration** - Strongly typed `Algorithm` enum and configuration objects
- **Protected Claims** - Critical claims (iss, sub, iat, exp, jti, sid) cannot be overridden for security
- **Flexible Validation** - Configurable required claims and audience validation
- **Session Tracking** - Built-in session ID (sid) and JWT ID (jti) generation using UUID v7
- **Comprehensive Exceptions** - Specific exceptions for expired, invalid, and malformed tokens
- **Timezone Support** - Type-safe timezone configuration with a comprehensive `Timezone` enum covering all PHP supported timezones

## Requirements

- PHP 8.1 or higher
- OpenSSL extension (for RSA/ECDSA algorithms)

## Installation

Install via Composer:

```bash
composer require dev-toolbelt/jwt-token-manager
```

## Quick Start

### 1. Generate RSA Keys (if you don't have them)

Before using the library, you'll need an RSA key pair for signing and verifying tokens. If you already have keys, skip to step 2.

#### Linux / macOS

Open your terminal and run:

```bash
# Generate private key (2048-bit)
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private.key -out public.key
```

#### Windows

**Option 1: Using Git Bash (recommended)**

If you have Git installed, open Git Bash and use the same commands as Linux/macOS:

```bash
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.key -out public.key
```

**Option 2: Using WSL (Windows Subsystem for Linux)**

```bash
wsl openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
wsl openssl rsa -pubout -in private.key -out public.key
```

**Option 3: Using OpenSSL for Windows**

1. Download OpenSSL from [slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)
2. Install and add to PATH
3. Open Command Prompt and run the same commands

#### Production Keys (4096-bit)

For production environments, consider using stronger 4096-bit keys:

```bash
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in private.key -out public.key
```

> **Security Note:** Keep your private key secure and never commit it to version control. Add `*.key` to your `.gitignore` file.

### 2. Basic Usage

```php
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\JwtTokenManager;

// Create configuration
$config = new JwtConfig(
    privateKey: file_get_contents('/path/to/private.key'),
    publicKey: file_get_contents('/path/to/public.key'),
    issuer: 'https://api.yourapp.com'
);

// Initialize the manager
$manager = new JwtTokenManager($config);

// Generate a token
$token = $manager->encode('user-123', [
    'name' => 'John Doe',
    'role' => 'admin'
]);

// Decode and validate the token
$payload = $manager->decode($token);

echo $payload->getSubject();      // "user-123"
echo $payload->getClaim('name');  // "John Doe"
echo $payload->getClaim('role');  // "admin"
```

## Configuration

### Basic Configuration

```php
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\Enums\Security\Algorithm;
use DevToolbelt\Enums\Locale\Timezone;

$config = new JwtConfig(
    privateKey: $privateKey,
    publicKey: $publicKey,
    issuer: 'https://api.yourapp.com',
    algorithm: Algorithm::RS256,        // Default: RS256
    ttlMinutes: 60,                     // Default: 60 (1 hour)
    refreshTtlMinutes: 20160,           // Default: 20160 (14 days)
    audience: ['https://app.yourapp.com'],
    requiredClaims: ['iss', 'sub', 'exp', 'iat', 'jti', 'typ'],
    timezone: Timezone::AMERICA_SAO_PAULO  // Default: UTC
);
```

### Using Factory Methods

```php
// From key files
$config = JwtConfig::fromKeyFiles(
    privateKeyPath: '/path/to/private.key',
    publicKeyPath: '/path/to/public.key',
    issuer: 'https://api.yourapp.com'
);

// From array (useful for framework config files)
$config = JwtConfig::fromArray([
    'private_key' => $privateKey,
    'public_key' => $publicKey,
    'issuer' => 'https://api.yourapp.com',
    'algorithm' => 'RS256',
    'ttl_minutes' => 60,
    'audience' => ['https://app.yourapp.com'],
    'timezone' => 'America/Sao_Paulo'  // Or use Timezone enum
]);
```

### Supported Algorithms

| Algorithm | Type | Description |
|-----------|------|-------------|
| `HS256`, `HS384`, `HS512` | HMAC | Symmetric key algorithms |
| `RS256`, `RS384`, `RS512` | RSA | Asymmetric RSA algorithms |
| `ES256`, `ES384`, `ES512` | ECDSA | Elliptic Curve algorithms |
| `PS256`, `PS384`, `PS512` | RSA-PSS | RSA with PSS padding |
| `EdDSA` | EdDSA | Edwards-curve Digital Signature |

> **Why RS256 is the default?** RS256 (RSA with SHA-256) is the most widely adopted algorithm in the industry, offering an excellent balance between security and performance. It uses asymmetric keys, allowing you to share the public key for verification while keeping the private key secure. This makes it ideal for distributed systems and microservices architectures.

```php
use DevToolbelt\Enums\Security\Algorithm;

// Check algorithm properties
Algorithm::RS256->isAsymmetric();  // true
Algorithm::HS256->isSymmetric();   // true
Algorithm::RS256->isRSA();         // true
Algorithm::ES256->isECDSA();       // true
```

### Timezone Configuration

The library provides a type-safe `Timezone` enum with all PHP supported timezones. The default timezone is **UTC**.

```php
use DevToolbelt\Enums\Locale\Timezone;

// Using the enum directly
$config = new JwtConfig(
    privateKey: $privateKey,
    publicKey: $publicKey,
    issuer: 'https://api.yourapp.com',
    timezone: Timezone::AMERICA_SAO_PAULO
);

// Available timezone helper methods
Timezone::AMERICA_NEW_YORK->toDateTimeZone();    // Returns DateTimeZone instance
Timezone::EUROPE_LONDON->getUtcOffset();         // Returns offset in seconds
Timezone::ASIA_TOKYO->getUtcOffsetString();      // Returns "+09:00"

// Create from string (useful for config files)
$timezone = Timezone::from('America/Sao_Paulo');
$timezone = Timezone::tryFrom('Invalid/Zone');   // Returns null for invalid zones
```

Common timezone examples:
- **Americas**: `AMERICA_NEW_YORK`, `AMERICA_LOS_ANGELES`, `AMERICA_CHICAGO`, `AMERICA_SAO_PAULO`
- **Europe**: `EUROPE_LONDON`, `EUROPE_PARIS`, `EUROPE_BERLIN`, `EUROPE_MADRID`
- **Asia**: `ASIA_TOKYO`, `ASIA_SHANGHAI`, `ASIA_SINGAPORE`, `ASIA_DUBAI`
- **UTC**: `UTC`

> **Note**: JWT timestamps (`iat`, `exp`, `nbf`) are always Unix timestamps (seconds since Unix epoch), which are timezone-agnostic. The timezone configuration is used internally for consistent `DateTimeImmutable` operations and can be useful for logging, debugging, and future enhancements.

## Usage

### Generating Tokens

```php
$manager = new JwtTokenManager($config);

// Simple token with just a subject
$token = $manager->encode('user-123');

// Token with custom claims
$token = $manager->encode('user-123', [
    'name' => 'John Doe',
    'email' => 'john@example.com',
    'roles' => ['admin', 'editor'],
    'tenant_id' => 'tenant-456'
]);

// Get the generated session ID and JWT ID
$sessionId = $manager->getLastSessionId();  // UUID v7
$jti = $manager->getLastJti();              // UUID v7
```

### Token Claims

The generated token includes these standard claims:

| Claim | Description | Customizable |
|-------|-------------|--------------|
| `iss` | Issuer (from config) | No |
| `sub` | Subject (user identifier) | No |
| `aud` | Audience (from config) | Yes |
| `iat` | Issued at timestamp | No |
| `exp` | Expiration timestamp | No |
| `nbf` | Not before timestamp | Yes |
| `jti` | Unique JWT ID (UUID v7) | No |
| `sid` | Session ID (UUID v7) | No |
| `typ` | Token type (default: "access") | Yes |

> **Note**: Claims marked as **Customizable: No** are automatically generated and managed by the library to ensure token integrity and security. You cannot override these values.

### Decoding Tokens

Below is a comprehensive example showing all possible exceptions that can be thrown during token decoding and validation:

```php
try {
    $payload = $manager->decode($token);

    // Standard claim accessors
    $payload->getSubject();      // sub claim
    $payload->getIssuer();       // iss claim
    $payload->getAudience();     // aud claim (array)
    $payload->getExpiration();   // exp claim (timestamp)
    $payload->getIssuedAt();     // iat claim (timestamp)
    $payload->getNotBefore();    // nbf claim (timestamp)
    $payload->getJti();          // jti claim
    $payload->getSessionId();    // sid claim
    $payload->getType();         // typ claim

    // Custom claims
    $payload->getClaim('role');  // Get any custom claim
    $payload->hasClaim('role');  // Check if claim exists

    // Get all claims as array
    $allClaims = $payload->toArray();

    // Check expiration
    if ($payload->isExpired()) {
        // Token has expired
    }

} catch (ExpiredTokenException $e) {
    // Token has expired
} catch (InvalidSignatureException $e) {
    // Public key could not validate the token signature
} catch (InvalidTokenException $e) {
    // Token is malformed or not yet valid
} catch (InvalidClaimException $e) {
    // A claim validation failed
    $e->getClaimName();      // Which claim failed
    $e->getActualValue();    // What value was received
    $e->getExpectedValue();  // What was expected
} catch (MissingClaimsException $e) {
    // Required claims are missing
    $e->getMissingClaims();  // Array of missing claim names
}
```

### Refresh Tokens

While refresh tokens are not mandatory, implementing them is highly recommended for a secure authentication flow. The concept is simple: **access tokens should be short-lived** (minutes to hours) to minimize the impact if compromised, while **refresh tokens are long-lived** (days to weeks) and used solely to obtain new access tokens. This approach reduces the attack window for stolen tokens while maintaining a smooth user experience without frequent re-authentication.

```php
// Generate a refresh token
$refreshToken = $manager->generateRefreshToken();  // SHA1 hash

// Get TTL values
$accessTtl = $manager->getTokenTtl();        // In seconds
$refreshTtl = $manager->getRefreshTokenTtl(); // In seconds
```

> **Best Practice**: Store refresh tokens securely (e.g., in a database with the user association) and invalidate them when the user logs out or when suspicious activity is detected.

### Overriding Optional Claims

Some claims can be overridden via custom claims for flexibility:

```php
// Override the token type for refresh tokens
$refreshToken = $manager->encode('user-123', [
    'typ' => 'refresh'
]);

// Override not-before time
$token = $manager->encode('user-123', [
    'nbf' => time() + 3600  // Token valid in 1 hour
]);

// Override audience for specific consumers
$token = $manager->encode('user-123', [
    'aud' => ['https://mobile-app.yourapp.com']
]);
```

> **Note**: Protected claims (`iss`, `sub`, `iat`, `exp`, `jti`, `sid`) cannot be overridden for security reasons.

## Framework Integration Examples

### Laravel

```php
// config/jwt.php
return [
    'private_key' => storage_path('keys/private.key'),
    'public_key' => storage_path('keys/public.key'),
    'issuer' => env('APP_URL'),
    'audience' => [env('FRONTEND_URL')],
    'ttl_minutes' => 60,
];

// app/Providers/AppServiceProvider.php
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\JwtTokenManager;

public function register(): void
{
    $this->app->singleton(JwtTokenManager::class, function ($app) {
        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: config('jwt.private_key'),
            publicKeyPath: config('jwt.public_key'),
            issuer: config('jwt.issuer'),
            audience: config('jwt.audience'),
            ttlMinutes: config('jwt.ttl_minutes')
        );

        return new JwtTokenManager($config);
    });
}

// Usage in a controller or service
use DevToolbelt\JwtTokenManager\JwtTokenManager;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        // Using dependency injection
        $manager = app(JwtTokenManager::class);

        // Or using the helper with type hint
        /** @var JwtTokenManager $manager */
        $manager = app()->make(JwtTokenManager::class);

        $token = $manager->encode($user->id, [
            'name' => $user->name,
            'email' => $user->email
        ]);

        return response()->json(['token' => $token]);
    }
}
```

### Symfony

```yaml
# config/services.yaml
services:
    DevToolbelt\JwtTokenManager\JwtConfig:
        factory: ['DevToolbelt\JwtTokenManager\JwtConfig', 'fromKeyFiles']
        arguments:
            $privateKeyPath: '%kernel.project_dir%/config/keys/private.key'
            $publicKeyPath: '%kernel.project_dir%/config/keys/public.key'
            $issuer: '%env(APP_URL)%'

    DevToolbelt\JwtTokenManager\JwtTokenManager:
        arguments:
            $config: '@DevToolbelt\JwtTokenManager\JwtConfig'
```

```php
// src/Controller/AuthController.php
namespace App\Controller;

use DevToolbelt\JwtTokenManager\JwtTokenManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

class AuthController extends AbstractController
{
    public function __construct(
        private readonly JwtTokenManager $jwtManager
    ) {}

    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function login(): JsonResponse
    {
        $user = $this->getUser();

        $token = $this->jwtManager->encode($user->getId(), [
            'email' => $user->getEmail(),
            'roles' => $user->getRoles()
        ]);

        return $this->json(['token' => $token]);
    }
}
```

### Slim / PHP-DI

```php
// config/container.php
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\JwtTokenManager;
use Psr\Container\ContainerInterface;

return [
    JwtTokenManager::class => function (ContainerInterface $c) {
        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: __DIR__ . '/../keys/private.key',
            publicKeyPath: __DIR__ . '/../keys/public.key',
            issuer: $_ENV['APP_URL']
        );

        return new JwtTokenManager($config);
    },
];
```

```php
// src/Action/LoginAction.php
use DevToolbelt\JwtTokenManager\JwtTokenManager;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class LoginAction
{
    public function __construct(
        private readonly JwtTokenManager $jwtManager
    ) {}

    public function __invoke(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();

        // After validating credentials...
        $token = $this->jwtManager->encode($userId, [
            'email' => $data['email']
        ]);

        $response->getBody()->write(json_encode(['token' => $token]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
```

### CodeIgniter 4

```php
// app/Config/Services.php
namespace Config;

use CodeIgniter\Config\BaseService;
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\JwtTokenManager;

class Services extends BaseService
{
    public static function jwtManager(bool $getShared = true): JwtTokenManager
    {
        if ($getShared) {
            return static::getSharedInstance('jwtManager');
        }

        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: WRITEPATH . 'keys/private.key',
            publicKeyPath: WRITEPATH . 'keys/public.key',
            issuer: base_url()
        );

        return new JwtTokenManager($config);
    }
}
```

```php
// app/Controllers/Auth.php
namespace App\Controllers;

use Config\Services;

class Auth extends BaseController
{
    public function login()
    {
        $manager = Services::jwtManager();

        // After validating credentials...
        $token = $manager->encode($user->id, [
            'email' => $user->email,
            'name' => $user->name
        ]);

        return $this->response->setJSON(['token' => $token]);
    }
}
```

### CakePHP 5

```php
// config/services.php
use Cake\Core\Container;
use Cake\Core\ServiceProvider;
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\JwtTokenManager;

class JwtServiceProvider extends ServiceProvider
{
    protected array $provides = [JwtTokenManager::class];

    public function services(Container $container): void
    {
        $container->addShared(JwtTokenManager::class, function () {
            $config = JwtConfig::fromKeyFiles(
                privateKeyPath: CONFIG . 'keys/private.key',
                publicKeyPath: CONFIG . 'keys/public.key',
                issuer: env('APP_URL', 'https://localhost')
            );

            return new JwtTokenManager($config);
        });
    }
}

// In src/Application.php, register the provider:
// $container->addServiceProvider(new JwtServiceProvider());
```

```php
// src/Controller/AuthController.php
namespace App\Controller;

use DevToolbelt\JwtTokenManager\JwtTokenManager;

class AuthController extends AppController
{
    public function login()
    {
        $manager = $this->getContainer()->get(JwtTokenManager::class);

        // After validating credentials...
        $token = $manager->encode($user->id, [
            'email' => $user->email
        ]);

        return $this->response
            ->withType('application/json')
            ->withStringBody(json_encode(['token' => $token]));
    }
}
```

### Yii2

```php
// config/web.php
return [
    'components' => [
        'jwt' => [
            'class' => 'app\components\JwtComponent',
        ],
    ],
];
```

```php
// components/JwtComponent.php
namespace app\components;

use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\JwtTokenManager;
use yii\base\Component;

class JwtComponent extends Component
{
    private ?JwtTokenManager $manager = null;

    public function init(): void
    {
        parent::init();

        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: \Yii::getAlias('@app/config/keys/private.key'),
            publicKeyPath: \Yii::getAlias('@app/config/keys/public.key'),
            issuer: \Yii::$app->params['appUrl']
        );

        $this->manager = new JwtTokenManager($config);
    }

    public function getManager(): JwtTokenManager
    {
        return $this->manager;
    }
}
```

```php
// controllers/AuthController.php
namespace app\controllers;

use yii\rest\Controller;

class AuthController extends Controller
{
    public function actionLogin()
    {
        $manager = \Yii::$app->jwt->getManager();

        // After validating credentials...
        $token = $manager->encode($user->id, [
            'email' => $user->email,
            'name' => $user->name
        ]);

        return ['token' => $token];
    }
}
```

## Testing

```bash
# Run all tests
composer test

# Run with coverage
composer test:coverage

# Code quality
composer phpcs        # Check code style
composer phpcs:fix    # Fix code style
composer phpstan      # Static analysis
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and follow the existing code style.

## Security

If you discover any security-related issues, please email dersonsena@gmail.com instead of using the issue tracker.

## Credits

- [Kilderson Sena](https://github.com/dersonsena)
- [All Contributors](../../contributors)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and follow PSR-12 coding standards.

### Code Quality Requirements

| Check | Tool | Requirement |
|-------|------|-------------|
| Tests | PHPUnit | All tests must pass |
| Coverage | PCOV | Minimum **85%** coverage |
| Code Style | PHP CodeSniffer | PSR-12 compliant |
| Static Analysis | PHPStan | Level 6, no errors |

### Pull Request Guidelines

Before submitting a PR, ensure:

1. **All tests pass:** `composer test`
2. **Coverage is at least 85%:** `composer test:coverage`
3. **Code style is correct:** `composer phpcs`
4. **No static analysis errors:** `composer phpstan`

> **Important:** Pull requests with coverage below 85% will be automatically blocked by CI.

### Coverage Report

- **Dashboard:** [Codecov](https://codecov.io/gh/dev-toolbelt/jwt-token-manager)
- **HTML Report:** [GitHub Pages](https://dev-toolbelt.github.io/jwt-token-manager/)

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Made with ❤️ by [Dev Toolbelt](https://github.com/Dev-Toolbelt)
