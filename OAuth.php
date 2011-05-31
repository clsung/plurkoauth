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
    public function signing_base($request, $consumer, $token) {


    }

    public function sign($request, $consumer, $token) {
	$basestring = $this->signing_base($request, $consumer, $token);
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
    protected $key;
    protected $secret;

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
 * Request
 */
class Request
{
    protected $version = '1.0';
    protected $url;
    protected $method;
    protected $params;
    protected $body;
    protected $is_form_encoded;
    protected $oauth_timestamp;
    protected $oauth_nonce;
//    protected $normalized_url;

    function __construct($method = "POST", $url = null, $params=null,
	                 $body='', $is_form_encoded=false) {
	if (isset($url))
	    $this->url = urlencode($url);
	$this->method = $method;
	if (isset($params)) {
	    foreach ($params as $key => $value) {
		$self->params[urlencode($key)] = urlencode($value);
	    }
	}
	$this->method = $method;
	$this->body = $body;
	$this->is_form_encoded = $is_form_encoded;
    }

    function _get_timestamp_nonce() {
	return array($this->oauth_timestamp, $this->oauth_nonce);
    }

    function get_method() {
	return strtoupper($this->method);
    }

    function get_normalized_url() {
	$parsed = parse_url($self->url);
	$normalized_url = http_build_url(
	    array(
		"scheme" => $parsed['scheme'],
		"host"   => $parsed['host'],
		"path"   => $parsed['path']
		)
	    );
	return $normalized_url;
    }

    function get_nonoauth_parameters() {
	foreach ($params as $key => $value) {
	    if (substr_compare($key, 'oauth_', 0))
		$kv[$key] = $value;
	}
	return $kv;
    }

    function to_header($realm='') {

	foreach ($params as $key => $value) {
	    if (!substr_compare($key, 'oauth_', 0))
		$oauth_params[$key] = $value;
		$stringy_params[$key] = urlencode($value);
		array_push($header_params, sprintf("%s=%s", $key, $value));
	}
	$params_header = implode(", ", $header_params);
	$auth_header = sprintf('OAuth realm="%s"', $realm);
	if (isset($params_header))
	    $auth_header = sprintf("%s, %s", $auth_header, $params_header);

	return array ('Authorization' => $auth_header);
    }

    function to_postdata() {
	foreach ($this->params as $key => $value) {
	    array_push($parts,
		sprintf("%s=%s",rawurlencode($key),rawurlencode($value)));
	}
	return implode('&', rawurlencode(implode('&', $args_parts)));
    }
}

/**
 * Token
 */
class Token
{
    protected $key;
    protected $secret;
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
