<?php

declare(strict_types=1);

namespace DevToolbelt\JwtTokenManager\Tests\Unit;

use DateTimeZone;
use DevToolbelt\Enums\Locale\Timezone;
use DevToolbelt\Enums\Security\Algorithm;
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\Tests\TestCase;

final class JwtConfigTest extends TestCase
{
    private const FIXTURES_PATH = __DIR__ . '/../fixtures';

    private string $privateKey;
    private string $publicKey;

    protected function setUp(): void
    {
        parent::setUp();

        $this->privateKey = file_get_contents(self::FIXTURES_PATH . '/private.key');
        $this->publicKey = file_get_contents(self::FIXTURES_PATH . '/public.key');
    }

    public function testConstructorWithAllParameters(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::RS512,
            ttlMinutes: 30,
            refreshTtlMinutes: 10080,
            audience: ['https://app.example.com'],
            requiredClaims: ['iss', 'sub', 'exp']
        );

        $this->assertEquals($this->privateKey, $config->getPrivateKey());
        $this->assertEquals($this->publicKey, $config->getPublicKey());
        $this->assertEquals('https://api.example.com', $config->getIssuer());
        $this->assertEquals(Algorithm::RS512, $config->getAlgorithm());
        $this->assertEquals('RS512', $config->getAlgorithmValue());
        $this->assertEquals(30, $config->getTtlMinutes());
        $this->assertEquals(1800, $config->getTtlSeconds());
        $this->assertEquals(10080, $config->getRefreshTtlMinutes());
        $this->assertEquals(604800, $config->getRefreshTtlSeconds());
        $this->assertEquals(['https://app.example.com'], $config->getAudience());
        $this->assertEquals(['iss', 'sub', 'exp'], $config->getRequiredClaims());
    }

    public function testConstructorWithDefaultAlgorithm(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $this->assertEquals(Algorithm::RS256, $config->getAlgorithm());
        $this->assertEquals('RS256', $config->getAlgorithmValue());
    }

    public function testConstructorWithDefaultTtlMinutes(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $this->assertEquals(60, $config->getTtlMinutes());
        $this->assertEquals(3600, $config->getTtlSeconds());
    }

    public function testConstructorWithDefaultRefreshTtlMinutes(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $this->assertEquals(20160, $config->getRefreshTtlMinutes());
        $this->assertEquals(1209600, $config->getRefreshTtlSeconds());
    }

    public function testConstructorWithDefaultAudienceNull(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $this->assertNull($config->getAudience());
    }

    public function testConstructorWithDefaultRequiredClaims(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $expectedClaims = ['iss', 'jti', 'exp', 'iat', 'typ', 'sub'];
        $this->assertEquals($expectedClaims, $config->getRequiredClaims());
    }

    public function testFromArrayWithAllParameters(): void
    {
        $config = JwtConfig::fromArray([
            'private_key' => $this->privateKey,
            'public_key' => $this->publicKey,
            'issuer' => 'https://api.example.com',
            'algorithm' => 'RS384',
            'ttl_minutes' => 45,
            'refresh_ttl_minutes' => 15000,
            'audience' => ['https://app1.example.com', 'https://app2.example.com'],
            'required_claims' => ['iss', 'sub']
        ]);

        $this->assertEquals(Algorithm::RS384, $config->getAlgorithm());
        $this->assertEquals('RS384', $config->getAlgorithmValue());
        $this->assertEquals(45, $config->getTtlMinutes());
        $this->assertEquals(15000, $config->getRefreshTtlMinutes());
        $this->assertEquals(['https://app1.example.com', 'https://app2.example.com'], $config->getAudience());
        $this->assertEquals(['iss', 'sub'], $config->getRequiredClaims());
    }

    public function testFromArrayWithAlgorithmEnum(): void
    {
        $config = JwtConfig::fromArray([
            'private_key' => $this->privateKey,
            'public_key' => $this->publicKey,
            'issuer' => 'https://api.example.com',
            'algorithm' => Algorithm::HS256
        ]);

        $this->assertEquals(Algorithm::HS256, $config->getAlgorithm());
    }

    public function testFromArrayWithDefaults(): void
    {
        $config = JwtConfig::fromArray([
            'private_key' => $this->privateKey,
            'public_key' => $this->publicKey,
            'issuer' => 'https://api.example.com'
        ]);

        $this->assertEquals(Algorithm::RS256, $config->getAlgorithm());
        $this->assertEquals(60, $config->getTtlMinutes());
        $this->assertEquals(20160, $config->getRefreshTtlMinutes());
        $this->assertNull($config->getAudience());
        $this->assertEquals(['iss', 'jti', 'exp', 'iat', 'typ', 'sub'], $config->getRequiredClaims());
    }

    public function testFromArrayWithSingleAudienceString(): void
    {
        $config = JwtConfig::fromArray([
            'private_key' => $this->privateKey,
            'public_key' => $this->publicKey,
            'issuer' => 'https://api.example.com',
            'audience' => 'https://app.example.com'
        ]);

        $this->assertEquals(['https://app.example.com'], $config->getAudience());
    }

    public function testFromKeyFilesWithAllParameters(): void
    {
        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: self::FIXTURES_PATH . '/private.key',
            publicKeyPath: self::FIXTURES_PATH . '/public.key',
            issuer: 'https://api.example.com',
            algorithm: Algorithm::RS512,
            ttlMinutes: 120,
            refreshTtlMinutes: 30000,
            audience: ['https://app.example.com'],
            requiredClaims: ['iss', 'exp']
        );

        $this->assertEquals($this->privateKey, $config->getPrivateKey());
        $this->assertEquals($this->publicKey, $config->getPublicKey());
        $this->assertEquals(Algorithm::RS512, $config->getAlgorithm());
        $this->assertEquals('RS512', $config->getAlgorithmValue());
        $this->assertEquals(120, $config->getTtlMinutes());
        $this->assertEquals(30000, $config->getRefreshTtlMinutes());
        $this->assertEquals(['https://app.example.com'], $config->getAudience());
        $this->assertEquals(['iss', 'exp'], $config->getRequiredClaims());
    }

    public function testFromKeyFilesWithDefaults(): void
    {
        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: self::FIXTURES_PATH . '/private.key',
            publicKeyPath: self::FIXTURES_PATH . '/public.key',
            issuer: 'https://api.example.com'
        );

        $this->assertEquals($this->privateKey, $config->getPrivateKey());
        $this->assertEquals($this->publicKey, $config->getPublicKey());
        $this->assertEquals(Algorithm::RS256, $config->getAlgorithm());
        $this->assertEquals('RS256', $config->getAlgorithmValue());
        $this->assertEquals(60, $config->getTtlMinutes());
        $this->assertEquals(20160, $config->getRefreshTtlMinutes());
        $this->assertNull($config->getAudience());
        $this->assertEquals(['iss', 'jti', 'exp', 'iat', 'typ', 'sub'], $config->getRequiredClaims());
    }

    public function testConstructorWithDefaultTimezoneIsUtc(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com'
        );

        $this->assertEquals(Timezone::UTC, $config->getTimezone());
    }

    public function testConstructorWithCustomTimezone(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            timezone: Timezone::AMERICA_SAO_PAULO
        );

        $this->assertEquals(Timezone::AMERICA_SAO_PAULO, $config->getTimezone());
    }

    public function testGetDateTimeZoneReturnsDateTimeZoneInstance(): void
    {
        $config = new JwtConfig(
            privateKey: $this->privateKey,
            publicKey: $this->publicKey,
            issuer: 'https://api.example.com',
            timezone: Timezone::EUROPE_LONDON
        );

        $dateTimeZone = $config->getDateTimeZone();

        $this->assertInstanceOf(DateTimeZone::class, $dateTimeZone);
        $this->assertEquals('Europe/London', $dateTimeZone->getName());
    }

    public function testFromArrayWithTimezoneString(): void
    {
        $config = JwtConfig::fromArray([
            'private_key' => $this->privateKey,
            'public_key' => $this->publicKey,
            'issuer' => 'https://api.example.com',
            'timezone' => 'America/New_York'
        ]);

        $this->assertEquals(Timezone::AMERICA_NEW_YORK, $config->getTimezone());
    }

    public function testFromArrayWithTimezoneEnum(): void
    {
        $config = JwtConfig::fromArray([
            'private_key' => $this->privateKey,
            'public_key' => $this->publicKey,
            'issuer' => 'https://api.example.com',
            'timezone' => Timezone::ASIA_TOKYO
        ]);

        $this->assertEquals(Timezone::ASIA_TOKYO, $config->getTimezone());
    }

    public function testFromArrayWithDefaultTimezone(): void
    {
        $config = JwtConfig::fromArray([
            'private_key' => $this->privateKey,
            'public_key' => $this->publicKey,
            'issuer' => 'https://api.example.com'
        ]);

        $this->assertEquals(Timezone::UTC, $config->getTimezone());
    }

    public function testFromKeyFilesWithTimezone(): void
    {
        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: self::FIXTURES_PATH . '/private.key',
            publicKeyPath: self::FIXTURES_PATH . '/public.key',
            issuer: 'https://api.example.com',
            timezone: Timezone::AMERICA_SAO_PAULO
        );

        $this->assertEquals(Timezone::AMERICA_SAO_PAULO, $config->getTimezone());
    }

    public function testFromKeyFilesWithDefaultTimezone(): void
    {
        $config = JwtConfig::fromKeyFiles(
            privateKeyPath: self::FIXTURES_PATH . '/private.key',
            publicKeyPath: self::FIXTURES_PATH . '/public.key',
            issuer: 'https://api.example.com'
        );

        $this->assertEquals(Timezone::UTC, $config->getTimezone());
    }
}
