<?php declare(strict_types=1);
namespace App\Security;

use App\Entity\User;
use App\Service\DOMJudgeService;
use Doctrine\ORM\EntityManagerInterface;
use Its\Sso\OpenIDConnectClient;
use Its\Sso\OpenIDConnectClientException;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class MyITSSSOAuthenticator extends AbstractAuthenticator
{
    use TargetPathTrait;
    
    private ContainerBagInterface $params;
    private EntityManagerInterface $em;
    private RouterInterface $router;
    private Security $security;
    protected DOMJudgeService $dj;

    public function __construct(
        ContainerBagInterface $params,
        EntityManagerInterface $em,
        Security $security,
        RouterInterface $router,
        DOMJudgeService $dj
    )
    {
        $this->params = $params;
        $this->em = $em;
        $this->security = $security;
        $this->router = $router;
        $this->dj = $dj;
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning `false` will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request): bool
    {
        // if there is already an authenticated user (likely due to the session)
        // then return null and skip authentication: there is no need.
        return !$this->security->getUser()
                && $request->attributes->get('_route') === 'oidc'
                && $request->isMethod('GET');
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $oidc = new OpenIDConnectClient(
                $this->params->get('openid.provider'), // authorization_endpoint
                $this->params->get('openid.client_id'), // Client ID
                $this->params->get('openid.client_secret') // Client Secret
            );
    
            $oidc->setRedirectURL($this->params->get('openid.redirect_uri')); // must be the same as you registered
            $oidc->addScope($this->params->get('openid.scope')); //must be the same as you registered
    
            if($this->params->get('kernel.environment') === 'dev') {
                // remove this if in production mode
                $oidc->setVerifyHost(false);
                $oidc->setVerifyPeer(false);
            }
            $oidc->authenticate(); //call the main function of myITS SSO login
    
            $_SESSION['id_token'] = $oidc->getIdToken(); // must be save for check session dan logout proccess
            $userSso = $oidc->requestUserInfo(); // this will return user information from myITS SSO database
    
            $em = $this->em;
    
            $nrp = $userSso->reg_id;
            /** @var ?User $user */
            $user = $em->getRepository(User::class)->findOneBy(['externalid' => $nrp]);
            $picture = file_get_contents($userSso->picture);
            $jpegType = !empty(array_filter($http_response_header, function($header) {
                return $header == 'Content-Type: image/jpeg';
            }));
            $pngType = !empty(array_filter($http_response_header, function($header) {
                return $header == 'Content-Type: image/png';
            }));

            $teamId = $nrp;
            if ($teamId && ($jpegType || $pngType)) {
                $path = $this->dj->assetPath(sprintf("%s.png", $teamId), 'team', true);
                if ($path) unlink($path);
                $path = $this->dj->assetPath(sprintf("%s.jpg", $teamId), 'team', true);
                if ($path) unlink($path);
                $path = sprintf("%s/public/images/teams/%s.%s", $this->dj->getDomjudgeWebappDir(), $teamId, ($pngType ? 'png' : 'jpg'));
                if ($path) {
                    file_put_contents($path, $picture);
                }
            }
    
            if (!$user) {
                throw new CustomUserMessageAuthenticationException('User is not registered');
            }
    
            if (!$user->getEnabled()) {
                throw new CustomUserMessageAuthenticationException('User account is disabled');
            }
    
            return new SelfValidatingPassport(new UserBadge($user->getUsername()));
        } catch (OpenIDConnectClientException $e) {
            throw new CustomUserMessageAuthenticationException('Unable to get information from myITS SSO');
        }
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // On success, redirect to the last page or the homepage if it was a user triggered action.
        if ($request->attributes->get('_route') === 'oidc'
            && $request->isMethod('GET')) {
            // Use target URL from session if set.
            if ($firewallName !== null &&
                $targetUrl = $this->getTargetPath($request->getSession(), $firewallName)) {
                $this->removeTargetPath($request->getSession(), $firewallName);
                return new RedirectResponse($targetUrl);
            }

            return new RedirectResponse($this->router->generate('root'));
        }
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new RedirectResponse($this->router->generate('oidc_error', [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        ], UrlGeneratorInterface::ABSOLUTE_URL));
    }
}