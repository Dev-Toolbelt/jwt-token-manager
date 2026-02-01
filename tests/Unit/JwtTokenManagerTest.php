<?php

declare(strict_types=1);

namespace DevToolbelt\JwtTokenManager\Tests\Unit;

use DevToolbelt\Enums\Locale\Timezone;
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\TokenPayload;
use DevToolbelt\JwtTokenManager\Tests\TestCase;
use DevToolbelt\JwtTokenManager\JwtTokenManager;
use DevToolbelt\JwtTokenManager\Exceptions\ExpiredTokenException;
use DevToolbelt\JwtTokenManager\Exceptions\InvalidSignatureException;
use DevToolbelt\JwtTokenManager\Exceptions\InvalidTokenException;

final class JwtTokenManagerTest extends TestCase
{
    private const FIXTURES_PATH = __DIR__ . '/../fixtures';

    private string $privateKey;
    private string $publicKey;
    private JwtTokenManager $manager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->privateKey = file_get_contents(self::FIXTURES_PATH . '/private.key');
        $this->publicKey = file_get_contents(self::FIXTURES_PATH . '/public.key');

        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            audience: ['https://app.example.com'],
            requiredClaims: ['iss', 'aud', 'jti', 'sid', 'exp', 'nbf', 'iat', 'typ', 'sub']
        );

        $this->manager = new JwtTokenManager($config);
    }

    public function testEncodeGeneratesValidToken(): void
    {
        $token = $this->manager->encode('user-123', ['role' => 'admin']);

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
        $this->assertCount(3, explode('.', $token));
    }

    public function testDecodeReturnsTokenPayload(): void
    {
        $token = $this->manager->encode('user-123', ['role' => 'admin']);
        $payload = $this->manager->decode($token);

        $this->assertInstanceOf(TokenPayload::class, $payload);
        $this->assertEquals('user-123', $payload->getSubject());
        $this->assertEquals('admin', $payload->getClaim('role'));
        $this->assertEquals('https://api.example.com', $payload->getIssuer());
        $this->assertContains('https://app.example.com', $payload->getAudience());
    }

    public function testGetLastSessionIdReturnsSessionIdAfterEncode(): void
    {
        $this->assertNull($this->manager->getLastSessionId());

        $this->manager->encode('user-123');

        $sessionId = $this->manager->getLastSessionId();
        $this->assertNotNull($sessionId);
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $sessionId
        );
    }

    public function testGetLastJtiReturnsJtiAfterEncode(): void
    {
        $this->assertNull($this->manager->getLastJti());

        $this->manager->encode('user-123');

        $jti = $this->manager->getLastJti();
        $this->assertNotNull($jti);
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $jti
        );
    }

    public function testGenerateRefreshTokenReturnsSha1Hash(): void
    {
        $token = $this->manager->generateRefreshToken();

        $this->assertNotEmpty($token);
        $this->assertEquals(40, strlen($token));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $token);
    }

    public function testGetTokenTtlReturnsSecondsFromConfig(): void
    {
        $this->assertEquals(3600, $this->manager->getTokenTtl());
    }

    public function testGetRefreshTokenTtlReturnsSecondsFromConfig(): void
    {
        $this->assertEquals(1209600, $this->manager->getRefreshTokenTtl());
    }

    public function testDecodeThrowsExceptionForInvalidToken(): void
    {
        $this->expectException(InvalidTokenException::class);

        $this->manager->decode('invalid.token.here');
    }

    public function testDecodeThrowsExceptionForExpiredToken(): void
    {
        $expiredConfig = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            ttlMinutes: -1,
            audience: ['https://app.example.com'],
            requiredClaims: ['iss', 'aud', 'jti', 'sid', 'exp', 'nbf', 'iat', 'typ', 'sub']
        );

        $expiredManager = new JwtTokenManager($expiredConfig);
        $token = $expiredManager->encode('user-123');

        $this->expectException(ExpiredTokenException::class);

        $this->manager->decode($token);
    }

    public function testTokenPayloadHasAllStandardClaims(): void
    {
        $token = $this->manager->encode('user-123');
        $payload = $this->manager->decode($token);

        $this->assertTrue($payload->hasClaim('iss'));
        $this->assertTrue($payload->hasClaim('aud'));
        $this->assertTrue($payload->hasClaim('sub'));
        $this->assertTrue($payload->hasClaim('exp'));
        $this->assertTrue($payload->hasClaim('iat'));
        $this->assertTrue($payload->hasClaim('nbf'));
        $this->assertTrue($payload->hasClaim('jti'));
        $this->assertTrue($payload->hasClaim('sid'));
        $this->assertTrue($payload->hasClaim('typ'));
    }

    public function testTokenPayloadToArrayReturnsAllClaims(): void
    {
        $token = $this->manager->encode('user-123', ['custom' => 'value']);
        $payload = $this->manager->decode($token);

        $array = $payload->toArray();

        $this->assertIsArray($array);
        $this->assertArrayHasKey('sub', $array);
        $this->assertArrayHasKey('custom', $array);
        $this->assertEquals('user-123', $array['sub']);
        $this->assertEquals('value', $array['custom']);
    }

    public function testTokenPayloadIsExpiredReturnsFalseForValidToken(): void
    {
        $token = $this->manager->encode('user-123');
        $payload = $this->manager->decode($token);

        $this->assertFalse($payload->isExpired());
    }

    public function testEncodeWithoutAudienceDoesNotIncludeAudClaim(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('user-123');
        $payload = $manager->decode($token);

        $this->assertFalse($payload->hasClaim('aud'));
    }

    public function testDecodeWithNullAudienceSkipsAudienceValidation(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('user-123');
        $payload = $manager->decode($token);

        $this->assertInstanceOf(TokenPayload::class, $payload);
        $this->assertEquals('user-123', $payload->getSubject());
    }

    public function testEncodeWithDefaultConfigValues(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $manager = new JwtTokenManager($config);

        $this->assertEquals(3600, $manager->getTokenTtl());
        $this->assertEquals(1209600, $manager->getRefreshTokenTtl());

        $token = $manager->encode('user-123');
        $payload = $manager->decode($token);

        $this->assertEquals('user-123', $payload->getSubject());
        $this->assertEquals('https://api.example.com', $payload->getIssuer());
    }

    public function testProtectedClaimsCannotBeOverridden(): void
    {
        $token = $this->manager->encode('user-123', [
            'iss' => 'https://malicious.com',
            'sub' => 'hacked-user',
            'iat' => 0,
            'exp' => 9999999999,
            'jti' => 'fake-jti',
            'sid' => 'fake-sid',
        ]);

        $payload = $this->manager->decode($token);

        $this->assertEquals('https://api.example.com', $payload->getIssuer());
        $this->assertEquals('user-123', $payload->getSubject());
        $this->assertNotEquals(0, $payload->getIssuedAt());
        $this->assertNotEquals(9999999999, $payload->getExpiration());
        $this->assertNotEquals('fake-jti', $payload->getJti());
        $this->assertNotEquals('fake-sid', $payload->getSessionId());
    }

    public function testNbfClaimCanBeOverridden(): void
    {
        $customNbf = time() - 60;

        $token = $this->manager->encode('user-123', [
            'nbf' => $customNbf,
        ]);

        $payload = $this->manager->decode($token);

        $this->assertEquals($customNbf, $payload->getNotBefore());
    }

    public function testTypClaimCanBeOverriddenForCustomTokenTypes(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $manager = new JwtTokenManager($config);

        $token = $manager->encode('user-123', [
            'typ' => 'refresh',
        ]);

        // Decode raw JWT to verify typ was set (without validation)
        $parts = explode('.', $token);
        $payload = json_decode(base64_decode($parts[1]), false);

        $this->assertEquals('refresh', $payload->typ);
    }

    public function testAudienceCanBeOverriddenForDifferentConsumers(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            audience: ['https://default-app.example.com']
        );

        $manager = new JwtTokenManager($config);

        $token = $manager->encode('user-123', [
            'aud' => ['https://custom-app.example.com'],
        ]);

        // Decode raw JWT to verify aud was set
        $parts = explode('.', $token);
        $payload = json_decode(base64_decode($parts[1]), false);

        $this->assertEquals(['https://custom-app.example.com'], $payload->aud);

        // Verify it can be decoded by a manager configured for the custom audience
        $customConfig = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            audience: ['https://custom-app.example.com']
        );

        $customManager = new JwtTokenManager($customConfig);
        $decodedPayload = $customManager->decode($token);

        $this->assertEquals(['https://custom-app.example.com'], $decodedPayload->getAudience());
    }

    public function testDefaultTypClaimIsAccess(): void
    {
        $token = $this->manager->encode('user-123');
        $payload = $this->manager->decode($token);

        $this->assertEquals('access', $payload->getType());
    }

    public function testDefaultNbfClaimIsCurrentTimeMinusFiveSeconds(): void
    {
        $before = time() - 5;
        $token = $this->manager->encode('user-123');
        $after = time() - 5;

        $payload = $this->manager->decode($token);

        $this->assertGreaterThanOrEqual($before, $payload->getNotBefore());
        $this->assertLessThanOrEqual($after, $payload->getNotBefore());
    }

    public function testEncodeWithCustomTimezoneGeneratesValidToken(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            timezone: Timezone::AMERICA_SAO_PAULO
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('user-123');

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
        $this->assertCount(3, explode('.', $token));
    }

    public function testEncodeWithDifferentTimezonesGeneratesValidTimestamps(): void
    {
        $timezones = [
            Timezone::UTC,
            Timezone::AMERICA_NEW_YORK,
            Timezone::EUROPE_LONDON,
            Timezone::ASIA_TOKYO,
            Timezone::AMERICA_SAO_PAULO,
        ];

        foreach ($timezones as $timezone) {
            $config = new JwtConfig(
                privateKey: $this->privateKey,
                publicKey: $this->publicKey,
                issuer: 'https://api.example.com',
                timezone: $timezone
            );

            $manager = new JwtTokenManager($config);
            $beforeTime = time();
            $token = $manager->encode('user-123');
            $afterTime = time();

            $payload = $manager->decode($token);

            // Verify iat is within expected range
            $this->assertGreaterThanOrEqual($beforeTime, $payload->getIssuedAt());
            $this->assertLessThanOrEqual($afterTime, $payload->getIssuedAt());

            // Verify exp is iat + TTL (1 hour = 3600 seconds)
            $this->assertEquals(
                $payload->getIssuedAt() + 3600,
                $payload->getExpiration(),
                "Expiration should be iat + TTL for timezone {$timezone->value}"
            );
        }
    }

    public function testTokenGeneratedWithOneTimezoneCanBeDecodedByAnother(): void
    {
        // Generate token with Sao Paulo timezone
        $saoPauloConfig = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            timezone: Timezone::AMERICA_SAO_PAULO
        );

        $saoPauloManager = new JwtTokenManager($saoPauloConfig);
        $token = $saoPauloManager->encode('user-123');

        // Decode with Tokyo timezone - should work because timestamps are Unix timestamps (UTC)
        $tokyoConfig = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            timezone: Timezone::ASIA_TOKYO
        );

        $tokyoManager = new JwtTokenManager($tokyoConfig);
        $payload = $tokyoManager->decode($token);

        $this->assertEquals('user-123', $payload->getSubject());
        $this->assertFalse($payload->isExpired());
    }

    public function testGenerateRefreshTokenWithCustomTimezone(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            timezone: Timezone::EUROPE_PARIS
        );

        $manager = new JwtTokenManager($config);
        $refreshToken = $manager->generateRefreshToken();

        $this->assertNotEmpty($refreshToken);
        $this->assertEquals(40, strlen($refreshToken));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $refreshToken);
    }

    public function testDecodeThrowsInvalidSignatureExceptionForWrongPublicKey(): void
    {
        // Generate a token with the original keys
        $token = $this->manager->encode('user-123');

        // Load a different public key (not matching the private key used to sign)
        $differentPublicKey = file_get_contents(self::FIXTURES_PATH . '/different_public.key');

        // Create a manager with the wrong public key
        $wrongKeyConfig = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $differentPublicKey,
            issuer: 'https://api.example.com',
            audience: ['https://app.example.com'],
            requiredClaims: ['iss', 'aud', 'jti', 'sid', 'exp', 'nbf', 'iat', 'typ', 'sub']
        );

        $wrongKeyManager = new JwtTokenManager($wrongKeyConfig);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('Token signature verification failed');

        $wrongKeyManager->decode($token);
    }
}
