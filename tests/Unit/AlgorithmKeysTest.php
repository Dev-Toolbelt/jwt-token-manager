<?php

declare(strict_types=1);

namespace DevToolbelt\JwtTokenManager\Tests\Unit;

use DevToolbelt\JwtTokenManager\Algorithm;
use DevToolbelt\JwtTokenManager\JwtConfig;
use DevToolbelt\JwtTokenManager\JwtTokenManager;
use DevToolbelt\JwtTokenManager\Tests\TestCase;
use DevToolbelt\JwtTokenManager\TokenPayload;

/**
 * Tests for different cryptographic algorithm types.
 *
 * This test class verifies that the JWT Token Manager works correctly
 * with all supported algorithm families:
 * - HMAC (symmetric): HS256, HS384, HS512
 * - RSA (asymmetric): RS256, RS384, RS512
 * - ECDSA (asymmetric): ES256, ES384
 * - EdDSA (asymmetric): EdDSA (Ed25519)
 *
 * Note: PS256, PS384, PS512 (RSA-PSS) and ES512 are not supported by firebase/php-jwt.
 */
final class AlgorithmKeysTest extends TestCase
{
    private const FIXTURES_PATH = __DIR__ . '/../fixtures';

    // ==================== HMAC (Symmetric) Tests ====================

    public function testHs256SymmetricAlgorithm(): void
    {
        $secret = file_get_contents(self::FIXTURES_PATH . '/hmac_secret.key');

        $config = new JwtConfig(
            privateKey: $secret,
            publicKey: $secret,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::HS256
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('user-123', ['role' => 'admin']);

        $this->assertNotEmpty($token);
        $this->assertCount(3, explode('.', $token));

        $payload = $manager->decode($token);

        $this->assertInstanceOf(TokenPayload::class, $payload);
        $this->assertEquals('user-123', $payload->getSubject());
        $this->assertEquals('admin', $payload->getClaim('role'));
    }

    public function testHs384SymmetricAlgorithm(): void
    {
        $secret = file_get_contents(self::FIXTURES_PATH . '/hmac_secret.key');

        $config = new JwtConfig(
            privateKey: $secret,
            publicKey: $secret,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::HS384
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('user-456', ['permission' => 'read']);

        $payload = $manager->decode($token);

        $this->assertEquals('user-456', $payload->getSubject());
        $this->assertEquals('read', $payload->getClaim('permission'));
    }

    public function testHs512SymmetricAlgorithm(): void
    {
        $secret = file_get_contents(self::FIXTURES_PATH . '/hmac_secret.key');

        $config = new JwtConfig(
            privateKey: $secret,
            publicKey: $secret,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::HS512
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('user-789', ['level' => 'premium']);

        $payload = $manager->decode($token);

        $this->assertEquals('user-789', $payload->getSubject());
        $this->assertEquals('premium', $payload->getClaim('level'));
    }

    // ==================== RSA (Asymmetric) Tests ====================

    public function testRs256AsymmetricAlgorithm(): void
    {
        $privateKey = file_get_contents(self::FIXTURES_PATH . '/private.key');
        $publicKey = file_get_contents(self::FIXTURES_PATH . '/public.key');

        $config = new JwtConfig(
            privateKey: $privateKey,
            publicKey: $publicKey,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::RS256
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('rsa-user', ['algo' => 'RS256']);

        $payload = $manager->decode($token);

        $this->assertEquals('rsa-user', $payload->getSubject());
        $this->assertEquals('RS256', $payload->getClaim('algo'));
    }

    public function testRs384AsymmetricAlgorithm(): void
    {
        $privateKey = file_get_contents(self::FIXTURES_PATH . '/private.key');
        $publicKey = file_get_contents(self::FIXTURES_PATH . '/public.key');

        $config = new JwtConfig(
            privateKey: $privateKey,
            publicKey: $publicKey,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::RS384
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('rsa-user', ['algo' => 'RS384']);

        $payload = $manager->decode($token);

        $this->assertEquals('rsa-user', $payload->getSubject());
        $this->assertEquals('RS384', $payload->getClaim('algo'));
    }

    public function testRs512AsymmetricAlgorithm(): void
    {
        $privateKey = file_get_contents(self::FIXTURES_PATH . '/private.key');
        $publicKey = file_get_contents(self::FIXTURES_PATH . '/public.key');

        $config = new JwtConfig(
            privateKey: $privateKey,
            publicKey: $publicKey,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::RS512
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('rsa-user', ['algo' => 'RS512']);

        $payload = $manager->decode($token);

        $this->assertEquals('rsa-user', $payload->getSubject());
        $this->assertEquals('RS512', $payload->getClaim('algo'));
    }

    // ==================== ECDSA (Elliptic Curve) Tests ====================

    public function testEs256EcdsaAlgorithm(): void
    {
        $privateKey = file_get_contents(self::FIXTURES_PATH . '/ec256_private.key');
        $publicKey = file_get_contents(self::FIXTURES_PATH . '/ec256_public.key');

        $config = new JwtConfig(
            privateKey: $privateKey,
            publicKey: $publicKey,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::ES256
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('ec-user', ['algo' => 'ES256', 'curve' => 'P-256']);

        $payload = $manager->decode($token);

        $this->assertEquals('ec-user', $payload->getSubject());
        $this->assertEquals('ES256', $payload->getClaim('algo'));
        $this->assertEquals('P-256', $payload->getClaim('curve'));
    }

    public function testEs384EcdsaAlgorithm(): void
    {
        $privateKey = file_get_contents(self::FIXTURES_PATH . '/ec384_private.key');
        $publicKey = file_get_contents(self::FIXTURES_PATH . '/ec384_public.key');

        $config = new JwtConfig(
            privateKey: $privateKey,
            publicKey: $publicKey,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::ES384
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('ec-user', ['algo' => 'ES384', 'curve' => 'P-384']);

        $payload = $manager->decode($token);

        $this->assertEquals('ec-user', $payload->getSubject());
        $this->assertEquals('ES384', $payload->getClaim('algo'));
        $this->assertEquals('P-384', $payload->getClaim('curve'));
    }

    // ==================== EdDSA (Edwards-curve) Tests ====================

    public function testEdDsaAlgorithm(): void
    {
        // EdDSA requires base64-encoded raw sodium keys (firebase/php-jwt decodes internally)
        $privateKey = file_get_contents(self::FIXTURES_PATH . '/ed25519_private_raw.key');
        $publicKey = file_get_contents(self::FIXTURES_PATH . '/ed25519_public_raw.key');

        $config = new JwtConfig(
            privateKey: $privateKey,
            publicKey: $publicKey,
            issuer: 'https://api.example.com',
            algorithm: Algorithm::EdDSA
        );

        $manager = new JwtTokenManager($config);
        $token = $manager->encode('eddsa-user', ['algo' => 'EdDSA', 'curve' => 'Ed25519']);

        $payload = $manager->decode($token);

        $this->assertEquals('eddsa-user', $payload->getSubject());
        $this->assertEquals('EdDSA', $payload->getClaim('algo'));
        $this->assertEquals('Ed25519', $payload->getClaim('curve'));
    }

    // ==================== Cross-Algorithm Validation Tests ====================

    public function testAllSupportedAlgorithmsGenerateValidJwtStructure(): void
    {
        $algorithms = [
            'HS256' => [
                'algorithm' => Algorithm::HS256,
                'private' => '/hmac_secret.key',
                'public' => '/hmac_secret.key',
            ],
            'HS384' => [
                'algorithm' => Algorithm::HS384,
                'private' => '/hmac_secret.key',
                'public' => '/hmac_secret.key',
            ],
            'HS512' => [
                'algorithm' => Algorithm::HS512,
                'private' => '/hmac_secret.key',
                'public' => '/hmac_secret.key',
            ],
            'RS256' => [
                'algorithm' => Algorithm::RS256,
                'private' => '/private.key',
                'public' => '/public.key',
            ],
            'RS384' => [
                'algorithm' => Algorithm::RS384,
                'private' => '/private.key',
                'public' => '/public.key',
            ],
            'RS512' => [
                'algorithm' => Algorithm::RS512,
                'private' => '/private.key',
                'public' => '/public.key',
            ],
            'ES256' => [
                'algorithm' => Algorithm::ES256,
                'private' => '/ec256_private.key',
                'public' => '/ec256_public.key',
            ],
            'ES384' => [
                'algorithm' => Algorithm::ES384,
                'private' => '/ec384_private.key',
                'public' => '/ec384_public.key',
            ],
            'EdDSA' => [
                'algorithm' => Algorithm::EdDSA,
                'private' => '/ed25519_private_raw.key',
                'public' => '/ed25519_public_raw.key',
            ],
        ];

        foreach ($algorithms as $name => $algoConfig) {
            $privateKey = file_get_contents(self::FIXTURES_PATH . $algoConfig['private']);
            $publicKey = file_get_contents(self::FIXTURES_PATH . $algoConfig['public']);

            $config = new JwtConfig(
                privateKey: $privateKey,
                publicKey: $publicKey,
                issuer: 'https://api.example.com',
                algorithm: $algoConfig['algorithm']
            );

            $manager = new JwtTokenManager($config);
            $token = $manager->encode('test-user');

            // Verify JWT structure (header.payload.signature)
            $parts = explode('.', $token);
            $this->assertCount(3, $parts, "Algorithm {$name} should generate valid JWT structure");

            // Verify header contains correct algorithm
            $header = json_decode(base64_decode($parts[0]), true);
            $this->assertEquals($name, $header['alg'], "Algorithm header should be {$name}");
            $this->assertEquals('JWT', $header['typ'], "Type header should be JWT");

            // Verify payload can be decoded
            $payload = $manager->decode($token);
            $this->assertEquals('test-user', $payload->getSubject(), "Subject should match for {$name}");
        }
    }

    public function testSymmetricAlgorithmsUseIsSymmetricCorrectly(): void
    {
        $this->assertTrue(Algorithm::HS256->isSymmetric());
        $this->assertTrue(Algorithm::HS384->isSymmetric());
        $this->assertTrue(Algorithm::HS512->isSymmetric());

        $this->assertFalse(Algorithm::RS256->isSymmetric());
        $this->assertFalse(Algorithm::ES256->isSymmetric());
        $this->assertFalse(Algorithm::EdDSA->isSymmetric());
    }

    public function testAsymmetricAlgorithmsUseIsAsymmetricCorrectly(): void
    {
        $this->assertTrue(Algorithm::RS256->isAsymmetric());
        $this->assertTrue(Algorithm::RS384->isAsymmetric());
        $this->assertTrue(Algorithm::RS512->isAsymmetric());
        $this->assertTrue(Algorithm::ES256->isAsymmetric());
        $this->assertTrue(Algorithm::ES384->isAsymmetric());
        $this->assertTrue(Algorithm::EdDSA->isAsymmetric());

        $this->assertFalse(Algorithm::HS256->isAsymmetric());
        $this->assertFalse(Algorithm::HS384->isAsymmetric());
        $this->assertFalse(Algorithm::HS512->isAsymmetric());
    }

    public function testHmacAlgorithmsWorkWithSameKeyForSignAndVerify(): void
    {
        $secret = file_get_contents(self::FIXTURES_PATH . '/hmac_secret.key');

        foreach ([Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] as $algorithm) {
            $config = new JwtConfig(
                privateKey: $secret,
                publicKey: $secret,
                issuer: 'https://api.example.com',
                algorithm: $algorithm
            );

            $manager = new JwtTokenManager($config);
            $token = $manager->encode('hmac-user');
            $payload = $manager->decode($token);

            $this->assertEquals('hmac-user', $payload->getSubject());
            $this->assertTrue($algorithm->isSymmetric());
        }
    }

    public function testRsaAlgorithmsWorkWithDifferentKeysForSignAndVerify(): void
    {
        $privateKey = file_get_contents(self::FIXTURES_PATH . '/private.key');
        $publicKey = file_get_contents(self::FIXTURES_PATH . '/public.key');

        foreach ([Algorithm::RS256, Algorithm::RS384, Algorithm::RS512] as $algorithm) {
            $config = new JwtConfig(
                privateKey: $privateKey,
                publicKey: $publicKey,
                issuer: 'https://api.example.com',
                algorithm: $algorithm
            );

            $manager = new JwtTokenManager($config);
            $token = $manager->encode('rsa-user');
            $payload = $manager->decode($token);

            $this->assertEquals('rsa-user', $payload->getSubject());
            $this->assertTrue($algorithm->isAsymmetric());
            $this->assertTrue($algorithm->isRSA());
        }
    }

    public function testEcdsaAlgorithmsWorkWithEllipticCurveKeys(): void
    {
        $ecKeys = [
            ['algorithm' => Algorithm::ES256, 'private' => '/ec256_private.key', 'public' => '/ec256_public.key'],
            ['algorithm' => Algorithm::ES384, 'private' => '/ec384_private.key', 'public' => '/ec384_public.key'],
        ];

        foreach ($ecKeys as $keyConfig) {
            $algorithm = $keyConfig['algorithm'];
            $privateKey = file_get_contents(self::FIXTURES_PATH . $keyConfig['private']);
            $publicKey = file_get_contents(self::FIXTURES_PATH . $keyConfig['public']);

            $config = new JwtConfig(
                privateKey: $privateKey,
                publicKey: $publicKey,
                issuer: 'https://api.example.com',
                algorithm: $algorithm
            );

            $manager = new JwtTokenManager($config);
            $token = $manager->encode('ecdsa-user');
            $payload = $manager->decode($token);

            $this->assertEquals('ecdsa-user', $payload->getSubject());
            $this->assertTrue($algorithm->isAsymmetric());
            $this->assertTrue($algorithm->isECDSA());
        }
    }
}
