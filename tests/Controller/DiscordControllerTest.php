<?php

/*
 * This file is part of the Secret Santa project.
 *
 * (c) JoliCode <coucou@jolicode.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JoliCode\SecretSanta\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;

class DiscordControllerTest extends WebTestCase
{
    use SessionPrepareTrait;

    public function test_auth_page_redirects_to_discord(): void
    {
        $client = static::createClient();

        $crawler = $client->request('GET', '/auth/discord');
        $response = $client->getResponse();

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame(302, $response->getStatusCode());
        self::assertContains('https://discord.com/api/', $response->getTargetUrl());
    }
}
