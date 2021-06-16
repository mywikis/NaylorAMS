<?php
namespace MediaWiki\Extension\NaylorAMS;

use \MediaWiki\Auth\AuthManager;
use PluggableAuth as IPluggableAuthBase;
use PluggableAuthLogin;
use User;

class NaylorAMS extends IPluggableAuthBase {

    public function authenticate(&$id, &$username, &$realname, &$email, &$errorMsg) {
        // Initialize singletons
        $config = Config::newInstance();
        $authManager = AuthManager::singleton();
        $extraLoginFields = $authManager->getAuthenticationSessionData(PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY);

        $username = $extraLoginFields[ExtraLoginFields::USERNAME];
		$password = $extraLoginFields[ExtraLoginFields::PASSWORD];

        // Sanity checks
        if (!isset($username) || $username === '') {
            $errorMsg = 'Username is missing.';
            return false;
        }

        // Check if username is in deny list
        // This can be useful if there is a local-only user
        // and you don't want someone making an account on Naylor with the
        // exact same username to get into the account
        $usernameDenyList = $config->get('UsernameDenyList');

        if (in_array(ucfirst(strtolower($username)), $usernameDenyList, true)) {
            $errorMsg = 'This username is prohibited from logging in with Naylor AMS SSO.';
            return false;
        }

        // get $wgNaylorAMS_BaseUrl and $wgNaylorAMS_SecurityKey
        $baseUrl = $config->get('BaseUrl');
        $securityKey = $config->get('SecurityKey');

        if ($securityKey === '') {
            $errorMsg = 'Could not log in due to misconfigured wiki settings. Security key is missing.';
            return false;
        }

        // Make cURL request to Naylor AMS ValidateAuthenticationToken endpoint
        $validateAuthEndpoint = "$baseUrl/api/AuthenticateUser/";

        $validateAuthResult = NaylorAMS::timberlakeRequest(
            $validateAuthEndpoint,
            array(
                'username' => $username,
                'password' => $password
            ),
            $securityKey
        );
        
        $naylorUserId = (string) $validateAuthResult->AuthenticateUserResult;

        if ($naylorUserId === '') {
            $errorMsg = 'The Naylor user\'s contact ID could not be retrieved. This may indicate the authentication token was invalid.';
            return false;
        }

        $basicInfoEndpoint = "$baseUrl/api/GetBasicMemberInfo/";
        $userDetailsResult = NaylorAMS::timberlakeRequest(
            $basicInfoEndpoint,
            array(
                'ContactID' => $naylorUserId,
            ),
            $securityKey
        );
        
        $email = (string) $userDetailsResult->EmailAddress;
        $realname = ((string) $userDetailsResult->FirstName) . ' ' . ((string) $userDetailsResult->LastName);

        // Check if user already exists; otherwise, leave $id invalid and make a new user
        $user = User::newFromName($username);
		if ( $user !== false && $user->getId() !== 0 ) {
			$id = $user->getId();
        }
        
        return true;
    }

    public function saveExtraAttributes($id) {
        // do nothing
    }

    public function deauthenticate(User &$user) {
        $user = null;
    }

    /*
     * Makes a REST call to the API using cURL
    */
    protected static function timberlakeRequest($endpoint, $params, $securityKey) {
        $postFields = array_merge(
            $params,
            array(
                'securityKey' => $securityKey
            )
        );
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $endpoint);
        // curl_setopt($ch, CURLOPT_GET, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postFields));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, '5');
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); 
        $responseStr = curl_exec($ch);
        curl_close($ch);
        $responseArr = simplexml_load_string($responseStr);
        return $responseArr;
    }
}
