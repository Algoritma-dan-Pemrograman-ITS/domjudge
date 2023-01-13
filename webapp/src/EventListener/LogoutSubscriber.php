<?php

namespace App\EventListener;

use Its\Sso\OpenIDConnectClient;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class LogoutSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private ContainerBagInterface $params,
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [LogoutEvent::class => 'onLogout'];
    }

    public function onLogout(LogoutEvent $event): void
    {
        $request = $event->getRequest();
        $idToken = $request->query->get('id_token_hint');
        if (!$idToken) {
            return;
        }

        $redirectUri = $this->params->get('openid.post_logout_redirect_uri');
        $provider = $this->params->get('openid.provider');
        $clientId = $this->params->get('openid.client_id');
        $clientSecret = $this->params->get('openid.client_secret');
        $environment = $this->params->get('kernel.environment');

        $oidc = new OpenIDConnectClient($provider, $clientId, $clientSecret);
        if($environment === 'dev') {
            $oidc->setVerifyHost(false);
            $oidc->setVerifyPeer(false);
        }

        $oidc->signOut($idToken, $redirectUri);
    }
}