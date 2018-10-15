<?php

/*
 * This file is part of the Secret Santa project.
 *
 * (c) JoliCode <coucou@jolicode.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JoliCode\SecretSanta\Controller;

use JoliCode\SecretSanta\Application\FacebookApplication;
use JoliCode\SecretSanta\Exception\AuthenticationException;
use JoliCode\SecretSanta\User;
use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Provider\FacebookUser;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;

class FacebookController extends AbstractController
{
    private $facebookClientId;
    private $facebookClientSecret;
    private $router;

    public function __construct(string $facebookClientId, string $facebookClientSecret, RouterInterface $router)
    {
        $this->router = $router;
        $this->facebookClientId = $facebookClientId;
        $this->facebookClientSecret = $facebookClientSecret;
    }

    /**
     * Ask for Slack authentication and store the AccessToken in Session.
     */
    public function authenticate(Request $request, FacebookApplication $facebookApplication): Response
    {
        $session = $request->getSession();

        $provider = new Facebook([
            'clientId' => $this->facebookClientId,
            'clientSecret' => $this->facebookClientSecret,
            'redirectUri' => $this->router->generate('facebook_authenticate', [], RouterInterface::ABSOLUTE_URL),
            'graphApiVersion' => 'v3.1',
        ]);

        if ($request->query->has('error')) {
            return $this->redirectToRoute('homepage');
        }

        if (!$request->query->has('code')) {
            // If we don't have an authorization code then get one
            $options = [
                'scope' => [
                    'user_friends',
                ], // array or string
            ];
            $authUrl = $provider->getAuthorizationUrl($options);

            $session->set(FacebookApplication::SESSION_KEY_STATE, $provider->getState());

            return new RedirectResponse($authUrl);
        // Check given state against previously stored one to mitigate CSRF attack
        } elseif (empty($request->query->get('state')) || ($request->query->get('state') !== $session->get(FacebookApplication::SESSION_KEY_STATE))) {
            $session->remove(FacebookApplication::SESSION_KEY_STATE);

            throw new AuthenticationException('Invalid OAuth state');
        }

        try {
            // Try to get an access token (using the authorization code grant)
            $token = $provider->getAccessToken('authorization_code', [
                'code' => $request->query->get('code'),
            ]);

            // Who Am I?
            /** @var FacebookUser $user */
            $user = $provider->getResourceOwner($token);
        } catch (\Exception $e) {
            throw new AuthenticationException('Failed to retrieve data from Facebook', 0, $e);
        }

        $facebookApplication->setToken($token);
        $facebookApplication->setAdmin(new User($user->getId(), $user->getName()));

        return new RedirectResponse($this->router->generate('run', [
            'application' => $facebookApplication->getCode(),
        ]));
    }
}
