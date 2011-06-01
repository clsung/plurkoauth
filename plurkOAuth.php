<?php
/* 
 * Cheng-Lung Sung (clsung_AT_gmail.com) http://clsung.tw/
 *
 * A demo PHP Library supporting Plurk OAuth API
 */
require('config.php');
require('OAuth.php');

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
    protected $sign_method;
    protected $params;
    protected $consumer_key;
    protected $consumer;
    protected $client;

    function __construct($consumer_key, $consumer_secret,
	$access_token = NULL, $access_secret = NULL) {
	$this->consumer = new Consumer($consumer_key, $consumer_secret);
	$this->consumer_key = $consumer_key;
	$this->consumer_secret = $consumer_secret;
	$this->sign_method = new SignatureMethod_HMAC_SHA1();
	$this->params = array();
	if (!empty($access_token) && !empty($access_secret)) {
	    $this->authorize($access_token, $access_secret);
	}
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

    function request($path, $params, $content) {
	if (isset($params)) 
	    $params = array_merge ($params, $this->params);
	else
	    $params = $this->params;
	if (isset ($this->access_token))
	    $this->token = new Token(
		$this->access_token['oauth_token'], 
		$this->access_token['oauth_token_secret']); 
	else
	    unset($this->token);
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
	    $resp = json_decode($client->request(
		$this->baseURL.$path, "POST", /*$request->to_header()*/null, $content));
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
