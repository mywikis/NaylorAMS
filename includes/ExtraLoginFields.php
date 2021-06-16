<?php
namespace MediaWiki\Extension\NaylorAMS;

class ExtraLoginFields extends \ArrayObject {

    const USERNAME = 'username';
    const PASSWORD = 'password';

    public function __construct($config) {
        parent::__construct([
            static::USERNAME => [
                'type' => 'string',
                'label' => wfMessage('userlogin-yourname'),
                'help' => wfMessage('authmanager-username-help'),
            ],
            static::PASSWORD => [
                'type' => 'password',
                'label' => wfMessage('userlogin-yourpassword'),
                'help' => wfMessage('authmanager-password-help'),
                'sensitive' => true,
            ]
        ]);
    }
}
