<?php
/* 
 * Cheng-Lung Sung (clsung_AT_gmail.com) http://clsung.tw/
 *
 * A demo PHP Library supporting Plurk OAuth API
 */
require('config.php');

define('PLURK_ACCESS_TOKEN_URL', "http://www.plurk.com/OAuth/access_token");
define('PLURK_AUTHORIZE_URL', "http://www.plurk.com/OAuth/authorize");
define('PLURK_REQUEST_TOKEN_URL', "http://www.plurk.com/OAuth/request_token");

class PlurkOAuth {

    public $baseURL = 'http://www.plurk.com';
    protected $status;
    protected $response;
    protected $request_token;
    protected $access_token;
    protected $verifier;
    protected $params;
    protected $consumer_key;

    function __construct($consumer_key, $consumer_secret,
	$access_token = NULL, $access_secret = NULL) {
	$this->consumer_key = $consumer_key;
	$this->consumer_secret = $consumer_secret;
	$this->params = array (
	    'consumer_key' => $consumer_key, 
	    'consumer_secret' => $consumer_secret,
	    'signature_methods'     => array('HMAC-SHA1')
	);
	if (!empty($access_token) && !empty($access_secret)) {
	    $this->authorize($access_token, $access_secret);
	}
    }

    function twoLegOAuth() {
	OAuthStore::instance("2Leg", $this->params);
    }

    function threeLegOAuth() {
	$store = OAuthStore::instance("Session", $this->params);
	$store->addServerToken('', '', $this->access_token['oauth_token'], $this->access_token['oauth_token_secret'], null, null);
    }

    function authorize($access_token = NULL, $access_secret = NULL) {
	if (!empty($access_token) && !empty($access_secret)) {
	    $this->access_token['oauth_token'] = $access_token;
	    $this->access_token['oauth_token_secret'] = $access_secret;
	} else {
	    $this->params['server_uri'] = $this->baseURL;
	    $this->params['request_token_uri'] = PLURK_REQUEST_TOKEN_URL;
	    $this->params['authorize_uri'] = PLURK_AUTHORIZE_URL;
	    $this->params['access_token_uri'] = PLURK_ACCESS_TOKEN_URL;
	    $this->threeLegOAuth();
	    try {
		$response =
		    OAuthRequester::requestRequestToken($this->consumer_key,
			0, Null, 'POST', $this->params);
	    } catch (OAuthException2 $e) {
		var_dump($e);
		exit;
	    }
	    $this->request_token['oauth_token'] = $response['token'];
	    $this->request_token['oauth_token_secret'] =
		$_SESSION['oauth_'.$this->consumer_key]['token_secret'];

	    printf ("Access the following URL to get authorized: \n");
	    printf ("%s?oauth_token=%s\n", PLURK_AUTHORIZE_URL,
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

	    $this->params['oauth_verifier'] = $this->verifier;
	    $this->params['oauth_token_secret'] =
		$this->request_token['oauth_token_secret'];
	    try {
		OAuthRequester::requestAccessToken($this->consumer_key,
		    $this->request_token['oauth_token'], 0, 'POST',
		    $this->params
		);
	    } catch (OAuthException2 $e) {
		var_dump($e);
		exit;
	    }
	    $this->access_token['oauth_token'] =
		$_SESSION['oauth_'.$this->consumer_key]['token'];
	    $this->access_token['oauth_token_secret'] =
		$_SESSION['oauth_'.$this->consumer_key]['token_secret'];
	}
    }

    function twoLeggedRequest($path, $params = NULL, $content = NULL) {
	$this->twoLegOAuth();
	return $this->request($path, $params, $content);
    }

    function threeLeggedRequest($path, $params = NULL, $content = NULL) {
	$this->threeLegOAuth();
	return $this->request($path, $params, $content);
    }

    function request($path, $params, $content) {
	if (isset($params)) 
	    $params = array_merge ($params, $this->params);
	else 
	    $params = $this->params;
	$request = new OAuthRequester($this->baseURL.$path,
	    'POST', $params, $content);
	$this->status = 0;
	$this->response['reason'] = null;
	try {
	    $this->response = $request->doRequest();
	} catch (OAuthException2 $e) {
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
