<?php

namespace App\Controller;

use App\Services\UtilityService;
use Firebase\JWT\JWK;
use \Firebase\JWT\JWT;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;

class LtiController extends AbstractController
{
    /** @var UtilityService $util */
    private $util;
    /** @var SessionInterface $session */
    private $session;
    /** @var Request $request */
    private $request;

    /**
     * @Route("/lti/authorize", name="lti_authorize")
     */
    public function ltiAuthorize(
        Request $request,
        SessionInterface $session,
        UtilityService $util
    ) {

        $this->request = $request;
        $this->session = $session;
        $this->util = $util;

        $this->saveRequestToSession();

        return $this->redirect($this->getAuthenticationResponseUrl());
    }

    /**
     * @Route("/lti/authorize/check", name="lti_authorize_check")
     */
    public function ltiAuthorizeCheck(
        Request $request,
        SessionInterface $session,
        UtilityService $util
    ) {
        $this->request = $request;
        $this->session = $session;
        $this->util = $util;

        $this->saveRequestToSession();
        $clientId = $this->session->get('client_id');

        $jwt = $this->session->get('id_token');
        if (!$jwt) {
            $this->util->exitWithMessage('ID token not received from Canvas.');
        }

        // Create token from JWT and public JWKs
        $jwks = $this->getPublicJwks();
        $publicKey = JWK::parseKeySet($jwks);
        JWT::$leeway = 60;
        $token = JWT::decode($jwt, $publicKey, ['RS256']);

        // Issuer should match previously defined issuer
        $this->claimMatchOrExit('iss', $this->session->get('iss'), $token->iss);

        // Audience should include the client id
        $this->claimMatchOrExit('aud', $clientId, $token->aud);

        // Authorized Party should include the client id
        $this->claimMatchOrExit('azp', $clientId, $token->azp);

        // Expiration should be after the current time
        if (date('U') >= $token->exp) {
            $this->util->exitWithMessage(sprintf('The "exp" provided is before the current time.'));
        }
        // Id token must contain a nonce. Should verify that nonce has not been received within a certain time window

        // Add Token to Session
        $this->saveTokenToSession($token);

        return $this->redirectToRoute(
            'authorize',
            [
                'lms_api_domain' => $this->session->get('lms_api_domain'),
                'lms_user_id' => $this->session->get('lms_user_id'),
                'lms_course_id' => $this->session->get('lms_course_id')
            ]
        );
    }

    private function claimMatchOrExit($claimType, $sessionClaim, $tokenClaim) {
        if(is_array($tokenClaim)) {
            if(in_array($sessionClaim, $tokenClaim)) {
                return true;
            }
        }
        else if($sessionClaim == $tokenClaim) {
            return true;
        }
        $this->util->exitWithMessage(sprintf('The "%s" provided does not match the expected value: %s.', $claimType, $sessionClaim));
    }

    private function saveTokenToSession($token) {
        try {
            $customFields = (array) $token->{'https://purl.imsglobal.org/spec/lti/claim/custom'};
            foreach ($customFields as $key => $val) {
                $this->session->set($key, $val);
            }

            $roleFields = (array) $token->{'https://purl.imsglobal.org/spec/lti/claim/roles'};
            $roles = [];
            foreach ($roleFields as $role) {
                $roleArr = explode('#', $role);
                $roles[] = trim($roleArr[1]);
            }
            $this->session->set('roles', array_values(array_unique($roles)));
        } catch (\Exception $e) {
            print_r($e->getMessage());
        }
    }

    private function saveRequestToSession()
    {
        try {
            $postParams = $this->request->request->all();

            foreach ($postParams as $key => $val) {
                $this->session->set($key, $val);
            }
        } catch (\Exception $e) {
            print_r($e->getMessage());
        }

        return;
    }

    protected function getAuthenticationResponseUrl()
    {
        $baseUrl = $this->session->get('iss');

        $params = [
            'lti_message_hint' => $this->session->get('lti_message_hint'),
            'client_id' => $this->session->get('client_id'),
            'redirect_uri' => $this->getLtiRedirectUri(),
            'login_hint' => $this->session->get('login_hint'),
            'state' => 'state123',
            'scope' => 'openid',
            'response_type' => 'id_token',
            'response_mode' => 'form_post',
            'nonce' => 'nonce',
            'prompt' => 'none',
        ];
        $queryStr = http_build_query($params);

        return "{$baseUrl}/api/lti/authorize_redirect?{$queryStr}";
    }

    protected function getPublicJwks()
    {
        $httpClient = HttpClient::create();
        /* URL may be different for other LMSes */
        $url = $this->session->get('iss') . '/api/lti/security/jwks';
        $response = $httpClient->request('GET', $url);

        $keys = $response->toArray();
        return $keys;
    }

    protected function getLtiRedirectUri()
    {
        return $this->request->server->get('APP_LTI_REDIRECT_URL');
    }
}
