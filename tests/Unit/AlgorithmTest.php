<?php

declare(strict_types=1);

namespace DevToolbelt\JwtTokenManager\Tests\Unit;

use DevToolbelt\Enums\Security\Algorithm;
use DevToolbelt\JwtTokenManager\Tests\TestCase;

final class AlgorithmTest extends TestCase
{
    public function testHmacAlgorithmsAreSymmetric(): void
    {
        $this->assertTrue(Algorithm::HS256->isSymmetric());
        $this->assertTrue(Algorithm::HS384->isSymmetric());
        $this->assertTrue(Algorithm::HS512->isSymmetric());
    }

    public function testRsaAlgorithmsAreAsymmetric(): void
    {
        $this->assertTrue(Algorithm::RS256->isAsymmetric());
        $this->assertTrue(Algorithm::RS384->isAsymmetric());
        $this->assertTrue(Algorithm::RS512->isAsymmetric());
    }

    public function testRsaPssAlgorithmsAreAsymmetric(): void
    {
        $this->assertTrue(Algorithm::PS256->isAsymmetric());
        $this->assertTrue(Algorithm::PS384->isAsymmetric());
        $this->assertTrue(Algorithm::PS512->isAsymmetric());
    }

    public function testEcdsaAlgorithmsAreAsymmetric(): void
    {
        $this->assertTrue(Algorithm::ES256->isAsymmetric());
        $this->assertTrue(Algorithm::ES384->isAsymmetric());
        $this->assertTrue(Algorithm::ES512->isAsymmetric());
    }

    public function testEddsaIsAsymmetric(): void
    {
        $this->assertTrue(Algorithm::EdDSA->isAsymmetric());
    }

    public function testIsRsaReturnsTrueForRsaAlgorithms(): void
    {
        $this->assertTrue(Algorithm::RS256->isRSA());
        $this->assertTrue(Algorithm::RS384->isRSA());
        $this->assertTrue(Algorithm::RS512->isRSA());
        $this->assertTrue(Algorithm::PS256->isRSA());
        $this->assertTrue(Algorithm::PS384->isRSA());
        $this->assertTrue(Algorithm::PS512->isRSA());
    }

    public function testIsRsaReturnsFalseForNonRsaAlgorithms(): void
    {
        $this->assertFalse(Algorithm::HS256->isRSA());
        $this->assertFalse(Algorithm::ES256->isRSA());
        $this->assertFalse(Algorithm::EdDSA->isRSA());
    }

    public function testIsEcdsaReturnsTrueForEcdsaAlgorithms(): void
    {
        $this->assertTrue(Algorithm::ES256->isECDSA());
        $this->assertTrue(Algorithm::ES384->isECDSA());
        $this->assertTrue(Algorithm::ES512->isECDSA());
    }

    public function testIsEcdsaReturnsFalseForNonEcdsaAlgorithms(): void
    {
        $this->assertFalse(Algorithm::RS256->isECDSA());
        $this->assertFalse(Algorithm::HS256->isECDSA());
        $this->assertFalse(Algorithm::EdDSA->isECDSA());
    }

    public function testAlgorithmValues(): void
    {
        $this->assertEquals('HS256', Algorithm::HS256->value);
        $this->assertEquals('RS256', Algorithm::RS256->value);
        $this->assertEquals('ES256', Algorithm::ES256->value);
        $this->assertEquals('PS256', Algorithm::PS256->value);
        $this->assertEquals('EdDSA', Algorithm::EdDSA->value);
    }

    public function testFromStringValue(): void
    {
        $this->assertEquals(Algorithm::RS256, Algorithm::from('RS256'));
        $this->assertEquals(Algorithm::HS512, Algorithm::from('HS512'));
        $this->assertEquals(Algorithm::ES384, Algorithm::from('ES384'));
    }
}
