<?php

declare(strict_types=1);

namespace DevToolbelt\JwtTokenManager\Tests\Unit;

use DateTimeZone;
use DevToolbelt\JwtTokenManager\Tests\TestCase;
use DevToolbelt\Enums\Locale\Timezone;

final class TimezoneTest extends TestCase
{
    public function testUtcTimezoneHasCorrectValue(): void
    {
        $this->assertEquals('UTC', Timezone::UTC->value);
    }

    public function testToDateTimeZoneReturnsDateTimeZoneInstance(): void
    {
        $dateTimeZone = Timezone::UTC->toDateTimeZone();

        $this->assertInstanceOf(DateTimeZone::class, $dateTimeZone);
        $this->assertEquals('UTC', $dateTimeZone->getName());
    }

    public function testToDateTimeZoneWithDifferentTimezones(): void
    {
        $this->assertEquals('America/New_York', Timezone::AMERICA_NEW_YORK->toDateTimeZone()->getName());
        $this->assertEquals('Europe/London', Timezone::EUROPE_LONDON->toDateTimeZone()->getName());
        $this->assertEquals('Asia/Tokyo', Timezone::ASIA_TOKYO->toDateTimeZone()->getName());
        $this->assertEquals('America/Sao_Paulo', Timezone::AMERICA_SAO_PAULO->toDateTimeZone()->getName());
    }

    public function testGetUtcOffsetReturnsInteger(): void
    {
        $offset = Timezone::UTC->getUtcOffset();

        $this->assertIsInt($offset);
        $this->assertEquals(0, $offset);
    }

    public function testGetUtcOffsetStringForUtc(): void
    {
        $offsetString = Timezone::UTC->getUtcOffsetString();

        $this->assertEquals('+00:00', $offsetString);
    }

    public function testGetUtcOffsetStringFormatsCorrectly(): void
    {
        // Note: These tests check format, not exact values since DST can change offsets
        $offsetString = Timezone::AMERICA_NEW_YORK->getUtcOffsetString();
        $this->assertMatchesRegularExpression('/^[+-]\d{2}:\d{2}$/', $offsetString);

        $offsetString = Timezone::EUROPE_LONDON->getUtcOffsetString();
        $this->assertMatchesRegularExpression('/^[+-]\d{2}:\d{2}$/', $offsetString);

        $offsetString = Timezone::ASIA_TOKYO->getUtcOffsetString();
        $this->assertMatchesRegularExpression('/^[+-]\d{2}:\d{2}$/', $offsetString);
    }

    public function testTimezoneCanBeCreatedFromString(): void
    {
        $timezone = Timezone::from('America/Sao_Paulo');

        $this->assertEquals(Timezone::AMERICA_SAO_PAULO, $timezone);
        $this->assertEquals('America/Sao_Paulo', $timezone->value);
    }

    public function testTryFromReturnsNullForInvalidTimezone(): void
    {
        $timezone = Timezone::tryFrom('Invalid/Timezone');

        $this->assertNull($timezone);
    }

    public function testAllTimezoneValuesAreValidPhpTimezones(): void
    {
        // Include backward compatibility timezones (legacy/alias names)
        $phpTimezones = DateTimeZone::listIdentifiers(DateTimeZone::ALL_WITH_BC);

        foreach (Timezone::cases() as $timezone) {
            $this->assertContains(
                $timezone->value,
                $phpTimezones,
                "Timezone {$timezone->value} is not a valid PHP timezone"
            );
        }
    }

    public function testCommonBrazilianTimezonesExist(): void
    {
        $this->assertEquals('America/Sao_Paulo', Timezone::AMERICA_SAO_PAULO->value);
        $this->assertEquals('America/Fortaleza', Timezone::AMERICA_FORTALEZA->value);
        $this->assertEquals('America/Recife', Timezone::AMERICA_RECIFE->value);
        $this->assertEquals('America/Manaus', Timezone::AMERICA_MANAUS->value);
        $this->assertEquals('America/Cuiaba', Timezone::AMERICA_CUIABA->value);
    }

    public function testCommonUsTimezonesExist(): void
    {
        $this->assertEquals('America/New_York', Timezone::AMERICA_NEW_YORK->value);
        $this->assertEquals('America/Chicago', Timezone::AMERICA_CHICAGO->value);
        $this->assertEquals('America/Denver', Timezone::AMERICA_DENVER->value);
        $this->assertEquals('America/Los_Angeles', Timezone::AMERICA_LOS_ANGELES->value);
    }

    public function testCommonEuropeanTimezonesExist(): void
    {
        $this->assertEquals('Europe/London', Timezone::EUROPE_LONDON->value);
        $this->assertEquals('Europe/Paris', Timezone::EUROPE_PARIS->value);
        $this->assertEquals('Europe/Berlin', Timezone::EUROPE_BERLIN->value);
        $this->assertEquals('Europe/Rome', Timezone::EUROPE_ROME->value);
        $this->assertEquals('Europe/Madrid', Timezone::EUROPE_MADRID->value);
    }

    public function testCommonAsianTimezonesExist(): void
    {
        $this->assertEquals('Asia/Tokyo', Timezone::ASIA_TOKYO->value);
        $this->assertEquals('Asia/Shanghai', Timezone::ASIA_SHANGHAI->value);
        $this->assertEquals('Asia/Singapore', Timezone::ASIA_SINGAPORE->value);
        $this->assertEquals('Asia/Dubai', Timezone::ASIA_DUBAI->value);
        $this->assertEquals('Asia/Kolkata', Timezone::ASIA_KOLKATA->value);
    }
}
