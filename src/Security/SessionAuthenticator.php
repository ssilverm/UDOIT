<?php

namespace App\Security;

use App\Entity\User; // your user entity
use App\Services\SessionService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class SessionAuthenticator extends AbstractAuthenticator
{
    private $em;
    private $sessionService;
    private LoggerInterface $logger;

    public function __construct(
        RequestStack $requestStack, 
        EntityManagerInterface $em, 
        SessionService $sessionService,
        LoggerInterface $logger,
    )
    {
        $requestStack->getCurrentRequest();
        $this->em = $em;
        $this->sessionService = $sessionService;
        $this->logger = $logger;
    }

    public function supports(Request $request): bool
    {
        $this->logger->error("supports()");
        return $this->sessionService->hasSession();
    }

    public function authenticate(Request $request): Passport
    {
        return new SelfValidatingPassport(new UserBadge($this->sessionService->getSession()->get('userId')));
    }

    /*
    public function getCredentials(Request $request)
    {
        $this->logger->error("getCredentials()");
        $session = $this->sessionService->getSession();
        $this->logger->error("creds are {$session->get('userId')}");
        return $session->get('userId');
    }

    public function checkCredentials($credentials, UserInterface $user) 
    {
        $this->logger->error("checkCredentials()");
        $this->logger->error("creds are: {$credentials}");
        return is_numeric($credentials);
    }
    

    public function getUser($userId, UserProviderInterface $userProvider)
    {
        $this->logger->error("getUser()");
        return $this->em->getRepository(User::class)->find($userId);
    }
     */

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?JsonResponse
    {
        $this->logger->error("onAuthenticationSuccess()");
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?JsonResponse
    {
        $this->logger->error("onAuthenticationFailure()");
        return null;
    }

    /*
    public function start(Request $request, AuthenticationException $exception = null) 
    {
        $this->logger->error("start()");
        $data = [
            // you might translate this message
            'message' => 'Session authentication failed.'
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        $this->logger->error("supportsRememberMe()");
    }
     */
}
