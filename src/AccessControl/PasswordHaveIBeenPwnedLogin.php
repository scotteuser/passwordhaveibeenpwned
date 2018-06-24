<?php

namespace Bolt\Extension\ScottEuser\PasswordHaveIBeenPwned\AccessControl;

use Bolt\AccessControl\Login;
use Bolt\Events\AccessControlEvent;
use Bolt\Events\AccessControlEvents;
use Bolt\Translation\Translator as Trans;
use Carbon\Carbon;
use Silex\Application;

/**
 * Login authentication handling.
 *
 * @author Scott Euser <scotteuser@gmail.com>
 */
class PasswordHaveIBeenPwnedLogin extends Login
{


    /**
     * @var array Bolt configuration.
     */
    protected $config;

    /**
     * {@inheritdoc}
     */
    public function __construct(Application $app, $config)
    {
        parent::__construct($app);
        $this->app = $app;
        $this->config = $config;
    }

    /**
     * Check a user login request for username/password combinations.
     *
     * @param string             $userName
     * @param string             $password
     * @param AccessControlEvent $event
     *
     * @return bool
     */
    protected function loginCheckPassword($userName, $password, AccessControlEvent $event)
    {

        // Securely retrieve the total number of times this password has been in a breach.
        $haveibeenpwned = $this->app['access_control.haveibeenpwned'];
        $breach_count = $haveibeenpwned->getPasswordPwnedCount($password);
        $allow_login = $this->config['haveibeenpwned']['allow_login_when_api_not_available'];

        if ($breach_count > 0) {
            // Prepare message from config.
            $message = Trans::__($this->config['haveibeenpwned']['breach_error_message']);
            $message = str_replace('@count', number_format((int) $breach_count), $message);
            $message = str_replace('@breach', 'breach' . ($breach_count != 1 ? 'es' : '' ), $message);

            $this->flashLogger->error($message);
            $this->dispatcher->dispatch(
                AccessControlEvents::LOGIN_FAILURE,
                $event->setReason(AccessControlEvents::FAILURE_PASSWORD)
            );

            return false;
        } elseif (-1 === $breach_count && true !== $allow_login) {
            $message = Trans::__(
                'Unable to check for known breaches.'
                . 'Logging in has been temporarily disabled until checks can again be made.'
            );
            $this->flashLogger->error($message);
            $this->dispatcher->dispatch(
                AccessControlEvents::LOGIN_FAILURE,
                $event->setReason(AccessControlEvents::FAILURE_PASSWORD)
            );

            return false;
        }

        return parent::loginCheckPassword($userName, $password, $event);
    }

    /**
     * {@inheritdoc}
     *
     * No change from parent class, but parent class method is private and can't be
     * called from here.
     */
    private function throttleUntil($attempts)
    {
        if ($attempts < 5) {
            return null;
        }
        $wait = pow(($attempts - 4), 2);

        return Carbon::create()->addSeconds($wait);
    }

}

