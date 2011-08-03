<?php
/* 
 * Cheng-Lung Sung (clsung_AT_gmail.com) http://clsung.tw/
 *
 * This OAuth library is inspired from python-oauth2
 */

/**
 * OAuthException
 */
class PlurkOAuthException extends Exception
{
}

/**
 * SignatureMethod
 */
abstract class SignatureMethod
{
    abstract public function signing_base($request, $consumer, $token);
    abstract public function sign($request, $consumer, $token);
    public function check($request, $consumer, $token, $signature) {
	$built = $this->sign($request, $consumer, $token);
	return $built == $signature;
    }
}
/**
 * SignatureMethod_HMAC_SHA1
 */
class SignatureMethod_HMAC_SHA1 extends SignatureMethod
{
    public $name = 'HMAC-SHA1';
    public function signing_base($request, $consumer, $token) {
	$sig = array(
	    rawurlencode($request->method),
	    rawurlencode($request->normalized_url),
	    rawurlencode($request->get_normalized_parameters()),
	    );
	$key = sprintf("%s&", rawurlencode($consumer->secret));
	if (isset($token)) {
	    $key .= rawurlencode($token->secret);
	}
	$raw = implode('&', $sig);
	return array ($key, $raw);

    }

    public function sign($request, $consumer, $token) {
	$key_raw = $this->signing_base($request, $consumer, $token);
	$basestring = base64_encode (hash_hmac('sha1', $key_raw[1], $key_raw[0], true));
	return rawurlencode($basestring);
    }

    public function check($request, $consumer, $token, $signature) {
	$built = $this->sign($request, $consumer, $token);
	return $built == $signature;
    }
}

/**
 * SignatureMethod_PLAINTEXT
 */
class SignatureMethod_PLAINTEXT extends SignatureMethod
{
    public $name = 'PLAINTEXT';
    public function signing_base($request, $consumer, $token) {
	$sig = sprintf("%s&", htmlspecialchars($consumer->secret));
	if (isset($token))
	    $sig .= sprintf("%s&", htmlspecialchars($token->secret));
	return array ($sig, $sig);
    }

    public function sign($request, $consumer, $token) {
	$base = $this->signing_base($request, $consumer, $token);
	return $base[1];
    }

}
/**
 * Helper functions
 */
function make_timestamp() {
    return time();
}

function generate_nonce($length = 8) {
    return generate_random_string($length);
}

function generate_verifier($length = 8) {
    return generate_random_string($length);
}

function generate_random_string($length = 8) {
    $chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    $string = '';
    for ($p = 0; $p < $length; $p++) {
	$string .= $chars[mt_rand(0, strlen($chars))];
    }
    return $string;
}
/**
 * Consumer
 */
class Consumer 
{
    public $key;
    public $secret;

    function __construct($key, $secret) {
	$this->key = $key;
	$this->secret = $secret;
    }

    function __toString() {
	return urlencode(
	    sprintf("oauth_consumer_key=%s&oauth_consumer_secret=%s",
		$this->key, $this->secret)
	);
    }
}

/**
 * Client
 */
class Client
{
    protected $method;
    protected $timeout;
    protected $cache;
    protected $proxy_info;
    const DEFAULT_POST_CONTENT_TYPE = 'application/x-www-form-urlencoded';

    function __construct($consumer, $token = null, $cache=null,
	$timeout=null, $proxy_info=null) {
	if(! $consumer instanceof Consumer)
	    throw new PlurkOAuthException("not Consumer");
	if(isset($token) and ! $token instanceof Token)
	    throw new PlurkOAuthException("not Token");
	$this->consumer = $consumer;
	$this->token = $token;
	$this->method = new SignatureMethod_HMAC_SHA1();
    }

    function set_signature_method($method) {
	if (!$method instanceof SignatureMethod)
	    throw new PlurkOAuthException("not SignatureMethod");
	$this->method = $method;
    }

    function request($uri, $method="GET", $headers=null, $body='') {

	if (!isset($headers))
	    $headers = array();

	if ($method == "POST") {
	    if (!isset($header['Content-Type']))
		$headers['Content-Type'] = self::DEFAULT_POST_CONTENT_TYPE;
	}
	$is_form_encoded = (isset($headers) and
	    $headers['Content-Type'] == self::DEFAULT_POST_CONTENT_TYPE);

	$parameters = null;

	if ($is_form_encoded and isset($body))
	    parse_str($body,$parameters);

	$req = Request::from_consumer_and_token($this->consumer,
		$this->token, $method, $uri,
		$parameters, $body, $is_form_encoded);
	$req->sign_request($this->method, $this->consumer, $this->token);
	$headers = array_merge($headers, $req->to_header());

	$parsed = parse_url($uri);
	$realm = http_build_url(
	    array(
		"scheme" => $parsed['scheme'],
		"host"   => $parsed['host'],
		)
	    );

	if ($is_form_encoded) {
	    return http_parse_message(
		http_post_fields($uri, $parameters, null, array(headers => $headers))
	    )->body;
	} elseif ($method == "GET")  {
	    $uri = $req->to_url();
	    return http_get($uri, array(headers => $headers));
	} else {
	    $headers = $req->to_header($realm);
	    return http_head($uri, array(headers => $headers));
	}

	return http_request($method, $uri, $body, array(headers => $headers));
    }
}

/**
 * Request
 */
class Request
{
    protected static $version = '1.0';
    private $props = array();

    function __construct($method = "POST", $url = null, $params=null,
	                 $body='', $is_form_encoded=false) {
	$this->url = $url;
	$this->method = $method;
	$this->params = array();
	if (isset($params)) {
	    foreach ($params as $key => $value) {
		$this->params[$key] = $value;
	    }
	}
	$this->method = $method;
	$this->body = $body;
	$this->is_form_encoded = $is_form_encoded;
    }

    public static function from_consumer_and_token(
	$consumer, $token=null, $http_method="POST", $http_url=null,
	$parameters=null, $body='', $is_form_encoded=False) {
	if (!isset($parameters))
	    $parameters = array();

	$defaults = array (
	    'oauth_consumer_key' => $consumer->key,
	    'oauth_timestamp' => make_timestamp(),
	    'oauth_nonce' => generate_nonce(),
	    'oauth_version' => Request::$version,
	);
	$parameters = array_merge($defaults, $parameters);

	if (isset($token)) {
	    $parameters['oauth_token'] = $token->key;
	    if (isset($token->verifier))
		$parameters['oauth_verifier'] = $token->verifier;
	}
	return new Request($http_method, $http_url, $parameters,
	    $body, $is_form_encoded);
    }

    public function __set($prop, $value) {
	$this->props[$prop] = $value;
	if ($prop == 'url') {
	    if (isset($value)) {
		$parsed = parse_url($this->props[$prop]);
		$this->props['normalized_url'] = 
		    $this->normalized_url = http_build_url(
			array(
			    "scheme" => $parsed['scheme'],
			    "host"   => $parsed['host'],
			    "path"   => $parsed['path']
			    )
			);
	    } else {
		unset($this->url);
		unset($this->normalized_url);
	    }
	}
    }

    public function &__get($prop) {
	if ($prop == "method") {
	    return strtoupper($this->props[$prop]);
	}
	return $this->props[$prop];
    }

    function _get_timestamp_nonce() {
	return array($this->oauth_timestamp, $this->oauth_nonce);
    }


    function get_nonoauth_parameters() {
	foreach ($this->params as $key => $value) {
	    if (strncmp($key, 'oauth_', 5))
		$kv[$key] = $value;
	}
	return $kv;
    }

    function to_header($realm='') {
	$header_params = array();
	foreach ($this->params as $key => $value) {
	    if (!strncmp($key, 'oauth_', 5)) {
		$oauth_params[$key] = $value;
		array_push($header_params, sprintf('%s="%s"', $key, htmlspecialchars($value)));
	    }
	}
	$params_header = implode(", ", $header_params);
	$auth_header = sprintf('OAuth realm="%s"', $realm);
	if (isset($params_header))
	    $auth_header = sprintf("%s, %s", $auth_header, $params_header);

	return array ('Authorization' => $auth_header);
    }

    function to_url() { // for GET
	// TODO
    }
    function to_postdata() { // for POST
	return $this->params;
    }

    function get_normalized_parameters() {
	$items = array();
	foreach ($this->params as $key => $value) {
	    if ($key == 'oauth_signature')
		continue;
	    if (is_array($value)) {
		$mtems = array_merge($value, $items);
	    } else {
		$items[$key] = $value;
	    }
	}
	ksort($items);
	$item_parts = array();
	foreach ($items as $key => $value) {
	    $item_parts[] =
		sprintf("%s=%s",rawurlencode($key),rawurlencode($value));
	}
	return implode('&', $item_parts);
    }

    function sign_request($signature_method, $consumer, $token) {
	if (!isset($this->params['oauth_consumer_key'])) {
	    $this->params['oauth_consumer_key'] = $consumer->key;
	}
	if (isset($token) and !isset($this->params['oauth_token']))
	    $this->params['oauth_token'] = $token->key;
	$signature_method = new SignatureMethod_HMAC_SHA1();
	$this->params['oauth_signature_method'] = $signature_method->name;
	$this->params['oauth_signature'] =
	    $signature_method->sign($this, $consumer, $token);
    }

}

/**
 * Token
 */
class Token
{
    public $key;
    public $secret;
    protected $callback;
    protected $callback_confirmed;
    protected $verifier;

    function __construct($key, $secret) {
	if (!isset($key) or !isset($secret)) 
	    throw new InvalidArgumentException("Must specify both key/secret!");
	$this->key = $key;
	$this->secret = $secret;
	$this->callback = null;
	$this->callback_confirmed = false;
	$this->verifier = null;
    }

    function __toString() {
	$string = sprintf("oauth_consumer_key=%s&oauth_consumer_secret=%s",
	                    $this->key, $this->secret);
	if ($this->callback_confirmed)
	    $string .= sprintf("&oauth_callback_confirmed=%s",
		$this->callback_confirmed);
	return urlencode($string);
    }

    function set_callback($callback) {
	$this->callback = $callback;
	$this->callback_confirmed = true;
    }

    function get_callback_url() {
	if (isset($this->verifier) and isset($this->callback)) {
	    // TODO
	    return $this->callback;
	}
    }

    function set_verifier($verifier = null) {
	if (isset($verifier))
	    $this->verifier = $verifier;
	else 
	    $this->verifier = gererate_verifier();
	$this->callback_confirmed = true;
    }
}
?>
