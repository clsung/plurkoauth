<?php
/* 
 * Cheng-Lung Sung (clsung_AT_gmail.com) http://clsung.tw/
 *
 * A demo PHP Library supporting Plurk OAuth API
 */
require('plurkOAuth.php');

class PlurkAPI {
    protected $_error;
    protected $_oauth;

    function __construct($consumer_key = NULL, $consumer_secret = NULL,
	$access_token = NULL, $access_secret = NULL) {
	if (!isset($consumer_key) and !isset($consumer_secret))
	    throw new InvalidArgumentException("Must specify both consumer key/secret!");
	$this->_oauth = new PlurkOAuth($consumer_key, $consumer_secret, $access_token, $access_secret);
	$this->_error = array (
	    'content' => null,
	    'code' => 0,
	    'reason' => null
	);
    }
   
    function authorize_with_verifier($verifier = NULL) {
	$this->_oauth->authorize_with_verifier($verifier);
    }

    function authorize($access_token = null, $access_secret = null) {
	$this->_oauth->authorize($access_token, $access_secret);
    }

    function get_access_token() {
        return $this->_oauth->get_access_token();
    }

    function get_request_token() {
        return $this->_oauth->get_request_token();
    }

    function callAPI($path, $params_array = null) {
	$this->_error = $this->_oauth->request($path, null, $params_array);
	return $this->_error['content'];
    }

    function errno() {
	return $this->_error['code'];
    }

    function error() {
	return $this->_error['reason'];
    }
}
?>
