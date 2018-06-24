<?php

namespace Bolt\Extension\ScottEuser\PasswordHaveIBeenPwned;

use Bolt\Extension\SimpleExtension;
use Bolt\Extension\ScottEuser\PasswordHaveIBeenPwned\AccessControl\PasswordHaveIBeenPwnedLogin;
use Bolt\Extension\ScottEuser\PasswordHaveIBeenPwned\Services\HaveIBeenPwnedService;
use Silex\Application;


/**
 * PasswordHaveIBeenPwnedExtension extension class.
 *
 * @author Scott Euser <scotteuser@gmail.com>
 */
class PasswordHaveIBeenPwnedExtension extends SimpleExtension
{

    /**
     * {@inheritdoc}
     */
    public function getDisplayName()
    {
        return 'Password Have I Been Pwned';
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultConfig()
    {
        return [
            'haveibeenpwned' => [
                'allow_login_when_api_not_available' => false,
                'breach_error_message' => 'Your password was used in @count known security @breach. '
                    . 'As a result, your login attempt has been blocked. '
                    . 'Please reset your password via the forgot password form.',
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function registerServices(Application $app)
    {

        // Make have I been pwned service generally available.
        $app['access_control.haveibeenpwned'] = $app->share(
            function ($app) {
                $haveibeenpwned = new HaveIBeenPwnedService(
                    $app
                );
                return $haveibeenpwned;
            }
        );

        // Extend Bolt login service.
        $app['access_control.login'] = $app->share(
            function ($app) {
                $login = new PasswordHaveIBeenPwnedLogin(
                    $app,
                    $this->getConfig()
                );
                return $login;
            }
        );
    }

}
