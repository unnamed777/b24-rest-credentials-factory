<?php
namespace nav\B24;

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\Request;

class CredentialsFactory {
    protected $parameterBag;

    public function __construct(ParameterBagInterface $parameterBag)
    {
        $this->parameterBag = $parameterBag;
    }

    public function createFile(): \nav\B24\OAuthCredentials\File
    {
        return new \nav\B24\OAuthCredentials\File([
            'filepath' => $this->parameterBag->get('b24.storage_file'),
            'clientId' => $this->parameterBag->get('b24.client_id'),
            'clientSecret' => $this->parameterBag->get('b24.client_secret'),
        ]);
    }

    public function createFileFromRequest(Request $request): \nav\B24\OAuthCredentials\CredentialsInterface
    {
        $credentials = $this->createFile();
        $credentials->set($this->getAuthData($request));

        return $credentials;
    }

    public function createMemoryFromRequest(Request $request): \nav\B24\OAuthCredentials\CredentialsInterface
    {
        return new \nav\B24\OAuthCredentials\Memory($this->getAuthData($request));
    }

    protected function getAuthData(Request $request): array
    {
        if ($request->get('auth')) {
            // App without interface (API only)
            $authData = $request->get('auth');
        } else {
            // App with interface
            $authData = [
                'domain' => $request->get('DOMAIN'),
                'access_token' => $request->get('AUTH_ID'),
                'refresh_token' => $request->get('REFRESH_ID'),
                'expires_in' => (int) $request->get('AUTH_EXPIRES'),
                'expires_at' => time() + $request->get('AUTH_EXPIRES'),
            ];
        }

        return $authData;
    }

    public function createFromWebhook(string $url): \nav\B24\WebHookCredentials\Memory
    {
        preg_match('#://(.*)/rest/(.*)/(.*)(?:/|$)#smiuU', $url, $matches);

        return new \nav\B24\WebHookCredentials\Memory([
            'domain' => $matches[1],
            'userId' => $matches[2],
            'token' => $matches[3],
        ]);
    }

    public function createFromConfigWebhook(): \nav\B24\WebHookCredentials\Memory
    {
        return $this->createFromWebhook($this->parameterBag->get('b24.webhook'));
    }
}
