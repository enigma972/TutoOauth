<?php
namespace App\Security;

use App\Repository\UserRepository;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Routing\RouterInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use App\Security\Exception\NotVerifiedEmailException;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use Symfony\Component\HttpFoundation\RedirectResponse;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class GithubAuthenticator extends SocialAuthenticator
{
    use TargetPathTrait;

    private $router;
    private $clientRegistry;
    private $users;

    public function __construct(RouterInterface $router, ClientRegistry $clientRegistry, UserRepository $users)
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->users = $users;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse($this->getLoginUrl());
    }

    public function supports(Request $request)
    {
        return 'oauth_check' === $request->attributes->get('_route') && $request->get('service') === 'github';
    }

    public function getCredentials(Request $request)
    {
        return $this->fetchAccessToken($this->getClient());
    }

    /**
     * @param \League\OAuth2\Client\Token\AccessToken $credentials
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        /** @var \League\OAuth2\Client\Provider\GithubResourceOwner $githubUser */
        $githubUser = $this->getClient()->fetchUserFromToken($credentials);

        // get github user email
        $response = HttpClient::create()->request(
            'GET',
            'https://api.github.com/user/emails',
            [
                'headers'   =>  [
                    'authorization' =>  "token {$credentials->getToken()}"
                ]
            ]
        );
        $emails = json_decode($response->getContent(), true);
        foreach ($emails as $email) {
            if ($email['primary'] === true && $email['verified'] === true) {
                $data = $githubUser->toArray();
                $data['email'] = $email['email'];
                $githubUser = new GithubResourceOwner($data);
            }
        }

        if ($githubUser->getEmail() === null) {
            throw new NotVerifiedEmailException();
        }

        return $this->users->findOrCreateFromGithubOauth($githubUser);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($request->hasSession()) {
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }

        return new RedirectResponse($this->getLoginUrl());
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);
        $loginUrl = $this->getLoginUrl();

        return new RedirectResponse($targetPath ?: $loginUrl);
    }

    public function getClient(): GithubClient
    {
        return $this->clientRegistry->getClient('github');
    }

    protected function getLoginUrl()
    {
        return $this->router->generate('app_login');
    }
}
