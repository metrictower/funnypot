<?php

declare(strict_types=1);

namespace Funnypot\Sensor\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Sensor\Assessment;
use Funnypot\Sensor\Detector;
use Funnypot\Sensor\Funnypot;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Detector is the judgement with no reporting attached — what a host with its own queue uses.
 * These assert it needs none of the delivery config and agrees with the full facade.
 */
final class DetectorTest extends TestCase
{
    private const CHROME = array(
        'Host' => 'app.example.com',
        'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language' => 'en-GB,en;q=0.9',
        'Accept-Encoding' => 'gzip, deflate, br',
        'Sec-Fetch-Mode' => 'navigate',
    );

    private function request(string $path): RequestContext
    {
        return new RequestContext('GET', $path, '', self::CHROME, null, 'app.example.com');
    }

    public function test_it_needs_no_key_no_self_ips_and_no_queue_path(): void
    {
        $detector = Detector::fromArray(array('own_routes' => Funnypot::ONLY_ON_404));

        self::assertTrue($detector->check($this->request('/.env'))->shouldReport());
    }

    public function test_it_still_demands_the_route_oracle(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"own_routes" is required/');

        Detector::fromArray(array());
    }

    public function test_it_agrees_with_the_full_facade(): void
    {
        $config = array('own_routes' => Funnypot::ONLY_ON_404);
        $detector = Detector::fromArray($config);
        $funnypot = Funnypot::fromArray($config + array(
            'base_url' => 'https://mainnet.example',
            'key' => 'test-key',
            'self_ips' => array('203.0.113.7'),
            'intel_db_path' => ':memory:',
        ));

        foreach (array('/', '/.env', '/robots.txt', '/wp-login.php', '/favicon.ico') as $path) {
            self::assertSame(
                $detector->check($this->request($path))->toArray(),
                $funnypot->check($this->request($path))->toArray(),
                $path . ' must judge identically either way'
            );
        }
    }

    public function test_ignore_templates_suppresses_detection_end_to_end(): void
    {
        $probe = $this->request('/.env');

        // Baseline: /.env is a reportable probe, and it names the ids driving it.
        $base = Detector::fromArray(array('own_routes' => Funnypot::ONLY_ON_404));
        $before = $base->check($probe);
        self::assertTrue($before->shouldReport());
        $ids = $before->templateIds();
        self::assertNotEmpty($ids);

        // Ignoring exactly those ids drops the evidence: it classifies clean and is not reported.
        $silenced = Detector::fromArray(array(
            'own_routes' => Funnypot::ONLY_ON_404,
            'ignore_templates' => $ids,
        ));
        $after = $silenced->check($probe);
        self::assertFalse($after->shouldReport());
        self::assertSame('clean', $after->kind());
        self::assertSame(array(), $after->templateIds());
    }

    public function test_ignore_templates_leaves_other_probes_reporting(): void
    {
        // Silencing one path's templates must not silence a different probe path.
        $base = Detector::fromArray(array('own_routes' => Funnypot::ONLY_ON_404));
        $envIds = $base->check($this->request('/.env'))->templateIds();
        self::assertNotEmpty($envIds);

        $detector = Detector::fromArray(array(
            'own_routes' => Funnypot::ONLY_ON_404,
            'ignore_templates' => $envIds,
        ));

        self::assertFalse($detector->check($this->request('/.env'))->shouldReport());
        self::assertTrue($detector->check($this->request('/.git/config'))->shouldReport());
    }

    public function test_ignore_templates_must_be_an_array(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/"ignore_templates" must be an array/');

        Detector::fromArray(array(
            'own_routes' => Funnypot::ONLY_ON_404,
            'ignore_templates' => 'git-config',
        ));
    }

    public function test_the_facade_plumbs_ignore_templates(): void
    {
        $probe = $this->request('/.env');
        $ids = Detector::fromArray(array('own_routes' => Funnypot::ONLY_ON_404))
            ->check($probe)->templateIds();
        self::assertNotEmpty($ids);

        $funnypot = Funnypot::fromArray(array(
            'base_url' => 'https://mainnet.example',
            'key' => 'test-key',
            'self_ips' => array('203.0.113.7'),
            'intel_db_path' => ':memory:',
            'own_routes' => Funnypot::ONLY_ON_404,
            'ignore_templates' => $ids,
        ));

        self::assertFalse($funnypot->check($probe)->shouldReport());
    }

    public function test_the_facade_exposes_its_detector(): void
    {
        $funnypot = Funnypot::fromArray(array(
            'base_url' => 'https://mainnet.example',
            'key' => 'test-key',
            'self_ips' => array('203.0.113.7'),
            'intel_db_path' => ':memory:',
            'own_routes' => Funnypot::ONLY_ON_404,
        ));

        self::assertInstanceOf(Detector::class, $funnypot->detector());
        self::assertSame(
            Assessment::AMBIENT,
            $funnypot->detector()->check($this->request('/robots.txt'))->kind()
        );
    }
}
