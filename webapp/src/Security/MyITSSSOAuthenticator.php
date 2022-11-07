<?php declare(strict_types=1);
namespace App\Security;

use App\Entity\Role;
use App\Entity\Team;
use App\Entity\TeamAffiliation;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Its\Sso\OpenIDConnectClient;
use Its\Sso\OpenIDConnectClientException;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
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

    public function __construct(
        ContainerBagInterface $params,
        EntityManagerInterface $em,
        Security $security,
        RouterInterface $router
    )
    {
        $this->params = $params;
        $this->em = $em;
        $this->security = $security;
        $this->router = $router;
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

        if (!$user) {
            $user = new User();
            $teamRole = $this->em->getRepository(Role::class)->findOneBy(['dj_role' => 'team']);
            $user
                ->setUsername($nrp)
                ->setExternalid($nrp)
                ->setPlainPassword(random_bytes(16))
                ->setEnabled(true)
                ->addUserRole($teamRole);
        }
        
        /** @var ?Team $team */
        $team = $em->getRepository(Team::class)->findOneBy(['externalid' => $nrp]);
        if (!$team) {
            $team = new Team();
            $itsAffiliation = $this->em->getRepository(TeamAffiliation::class)->findOneBy(['externalid' => 'its']);
            $team
                ->setExternalid($nrp)
                ->setAffiliation($itsAffiliation);
        }
        
        $team
            ->setName($userSso->name)
            ->setDisplayName($userSso->name)
            ->setPublicDescription(sprintf("Nama: %s\nNRP: %s", $userSso->name, $nrp));
        $em->persist($team);
        
        $user
            ->setName($userSso->name)
            ->setTeam($team);
        $em->persist($user);

        $em->flush();

        return new SelfValidatingPassport(new UserBadge($user->getUsername()));
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
        // We only throw an error if the credentials provided were wrong or the user doesn't exist.
        // Otherwise, we pass along to the next authenticator.
        if ($exception instanceof OpenIDConnectClientException || $exception instanceof UserNotFoundException) {
            $resp = new Response('', Response::HTTP_UNAUTHORIZED);
            return $resp;
        }

        // Let another guard authenticator handle it.
        return null;
    }
}