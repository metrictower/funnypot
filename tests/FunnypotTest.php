<?php

declare(strict_types=1);

namespace Funnypot\Sensor\Tests;

use Funnypot\Sensor\Funnypot;
use Funnypot\Core\Detection;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class FunnypotTest extends TestCase
{
    /** @return array<string,mixed> */
    private function config(array $overrides = array()): array
    {
        return array_merge(array(
            'base_url' => 'https://mainnet.example',
            'key' => 'test-key',
            'self_ips' => array('203.0.113.7'),
            'intel_db_path' => ':memory:',
        ), $overrides);
    }

    public function test_it_refuses_to_start_without_a_key(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"key" is required/');

        Funnypot::fromArray($this->config(array('key' => '')));
    }

    public function test_it_refuses_to_start_without_self_ips(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"self_ips" is required/');

        Funnypot::fromArray($this->config(array('self_ips' => array())));
    }

    public function test_it_refuses_to_start_without_a_queue_path(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"intel_db_path" is required/');

        Funnypot::fromArray($this->config(array('intel_db_path' => '')));
    }

    public function test_an_unmatched_detection_is_not_reportable(): void
    {
        $funnypot = Funnypot::fromArray($this->config());

        $this->assertFalse($funnypot->reportable(Detection::none()));
    }

    public function test_the_severity_floor_gates_reporting(): void
    {
        $high = Funnypot::fromArray($this->config(array('min_severity' => 'high')));
        $low = Funnypot::fromArray($this->config(array('min_severity' => 'low')));

        $medium = new Detection(true, array(), '', 'medium');

        $this->assertFalse($high->reportable($medium), 'medium is below a high floor');
        $this->assertTrue($low->reportable($medium), 'medium clears a low floor');
    }

    public function test_reporting_below_the_floor_does_not_queue(): void
    {
        $funnypot = Funnypot::fromArray($this->config(array('min_severity' => 'critical')));

        $result = $funnypot->report('198.51.100.9', new Detection(true, array(), '', 'info'));

        $this->assertSame(array('queued' => false, 'reason' => 'below severity floor'), $result);
    }
}
