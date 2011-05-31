<?php
/* 
 * Cheng-Lung Sung (clsung_AT_gmail.com) http://clsung.tw/
 *
 * A demo PHP Library supporting Plurk OAuth API
 */
require('plurkOAuth.php');

class PlurkAPI {
    protected $consumer_key;
    protected $consumer_secret;
    protected $_error;
    protected $_oauth;

    function __construct($consumer_key = NULL, $consumer_secret = NULL,
	$access_token = NULL, $access_secret = NULL) {
	if (!isset($consumer_key) and !isset($consumer_secret))
	    throw new InvalidArgumentException("Must specify both consumer key/secret!");
	$this->_oauth = new PlurkOAuth($consumer_key, $consumer_secret, $access_token, $access_secret);
	$this->consumer_key = $consumer_key;
	$this->consumer_secret = $consumer_secret;
	$this->_error = array (
	    'content' => null,
	    'code' => 0,
	    'reason' => null
	);
    }
   
    function callAPI($path, $params_array = null, $twolegged = false) {
	if ($twolegged) {
	    $this->_error = $this->_oauth->twoLeggedRequest($path, $params_array);
	} else {
	    $this->_error = $this->_oauth->threeLeggedRequest($path, $params_array);
	}
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
