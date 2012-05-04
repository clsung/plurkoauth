<?php
/* 
 * Cheng-Lung Sung (clsung_AT_gmail.com) http://clsung.tw/
 *
 * A demo PHP Library supporting Plurk OAuth API
 */
require('config.php');
require('OAuth.php');

define('PLURK_ACCESS_TOKEN_PATH', "/OAuth/access_token");
define('PLURK_AUTHORIZE_PATH', "/OAuth/authorize");
define('PLURK_REQUEST_TOKEN_PATH', "/OAuth/request_token");

class PlurkOAuth {

    public $baseURL = 'http://www.plurk.com';
    protected $status;
    protected $response;
    protected $request_token;
    protected $access_token;
    protected $verifier;
    protected $sign_method;
    protected $params;
    protected $consumer;
    protected $client;

    function __construct($consumer_key, $consumer_secret,
	$access_token = NULL, $access_secret = NULL) {
	$this->consumer = new Consumer($consumer_key, $consumer_secret);
	$this->sign_method = new SignatureMethod_HMAC_SHA1();
	$this->params = array();
	if (!empty($access_token) && !empty($access_secret)) {
	    $this->authorize($access_token, $access_secret);
	}
    }

    function _get_request_token() {
        unset($this->token);
        $sapi_type = php_sapi_name();
        if (substr($sapi_type, 0, 3) == 'cgi') {
            $content = $this->request(PLURK_REQUEST_TOKEN_PATH, null, array (
                'oauth_callback' => CALLBACK_URL));
        } else { # cli mode
            $content = $this->request(PLURK_REQUEST_TOKEN_PATH);
        }
	parse_str($content['content'], $this->request_token);
        setcookie('token', $this->request_token['oauth_token']);
        setcookie('secret', $this->request_token['oauth_token_secret']);
    }

    function _redirect_to_authorize() {
        printf ('<a href="%s?oauth_token=%s">Get Authorized</a>', $this->baseURL.PLURK_AUTHORIZE_PATH,
            $this->request_token['oauth_token']);
    }

    function _get_verifier() {
        printf ("Access the following URL to get authorized: \n");
        printf ("%s?oauth_token=%s\n", $this->baseURL.PLURK_AUTHORIZE_PATH,
            $this->request_token['oauth_token']);
        $handle = fopen ("php://stdin","r");
        $yes_no = "n";
        while (!strncmp($yes_no, "n", 1)) {
            printf("Input the verification number: ");
            $this->verifier = trim(fgets($handle));
            printf("Are you sure? (y/N) ");
            $yes_no = trim(fgets($handle));
            if (strncmp($yes_no, "y", 1)) $yes_no = "n";
        }
        fclose($handle);
    }

    function _get_access_token() {
	$content = $this->request(PLURK_ACCESS_TOKEN_PATH, null, array (
            'oauth_token' => $this->request_token['oauth_token'], 
	    'oauth_verifier' => $this->verifier,)
	);
	parse_str($content['content'], $this->access_token);
	if (isset($this->access_token['oauth_token'])) {
	    // XXX: print_r only for your first convenient,
	    //      you should store in config.php
	    print_r($this->access_token);
            unset($this->token);
	    $this->token = new Token(
		$this->access_token['oauth_token'], 
		$this->access_token['oauth_token_secret']); 
	    return true;
	}
	return false;
    }

    function authorize_with_verifier($verifier = NULL) {
        $this->verifier = $verifier;
        $this->request_token['oauth_token'] = $_COOKIE['token'];
        $this->request_token['oauth_token_secret'] = $_COOKIE['secret'];
        $this->token = new Token(
            $this->request_token['oauth_token'],
            $this->request_token['oauth_token_secret']);
        return $this->_get_access_token();
    }

    function get_access_token() {
        return $this->access_token;
    }

    function authorize($access_token = NULL, $access_secret = NULL) {
        $this->access_token['oauth_token'] = $access_token;
	if (!empty($access_secret)) {
	    $this->access_token['oauth_token_secret'] = $access_secret;
	    return true;
	} else {
            unset($this->access_token);
	    $this->_get_request_token();
            $sapi_type = php_sapi_name();
            if (substr($sapi_type, 0, 3) == 'cgi') {
                $this->_redirect_to_authorize();
                return false;
            } else { # cli mode
                $this->_get_verifier();
                return $this->_get_access_token();
            }
	}
    }

    function request($path, $params = null, $content = null) {
	if (isset($params)) 
	    $params = array_merge ($params, $this->params);
	else
	    $params = $this->params;
        if (isset ($this->access_token['oauth_token']) && 
            isset ($this->access_token['oauth_token_secret']))
	    $this->token = new Token(
		$this->access_token['oauth_token'], 
		$this->access_token['oauth_token_secret']); 
	$client = new Client($this->consumer, $this->token);

	$this->status = 0;
	$this->response['reason'] = null;
	try {
	    if (isset($content) and is_array($content)) {
		$content_params = array();
		foreach ($content as $key => $value) {
		    $content_params[] = 
			sprintf('%s=%s', rawurlencode($key), rawurlencode($value));
		}
		$content = implode('&', $content_params);
	    }
	    $resp = $client->request(
		$this->baseURL.$path, "POST", /*$request->to_header()*/null, $content);
	    if ($json = json_decode($resp))
		$resp = $json;
	    if (isset($resp->error_text)) {
		$this->status = -1;
		$this->response['body'] = null;
		$this->response['reason'] = $resp->error_text;
	    } else
		$this->response['body'] = $resp;
	} catch (PlurkOAuthException $e) {
	    $this->status = -1;
	    $this->response['reason'] = $e->getMessage();
	}
	return array( 'content' => $this->response['body'],
		    'code' => $this->status,
		    'reason' => $this->response['reason'],
		);
    }
};
?>
