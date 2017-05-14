<?

require('OAuth.php');

/*
class Request_Test extends PHPUnit_Framework_TestCase
{
    protected $request;
    public function setUp() {
    }
    public function testNormalizedURL() {
	$request = new Request("POST",
	    'https://www.plurk.com/OAuth/request_token', null, 'content');
	$this->assertEquals('https://www.plurk.com/OAuth/request_token',
	    $request->normalized_url);
    }
}
 */

class SignatureMethod_Test extends PHPUnit_Framework_TestCase
{
    protected $request;
    protected $consumer;
    protected $token;
    protected $signature_method;

    public function setUp() {
	$this->consumer = new Consumer('con_key', 'con_secret');
	$this->token = new Token('auth_token', 'auth_token_secret');
    }
    public function tearDown() {}

    public function testPOSTGetRequestToken() {
	$request = new Request("POST",
	    'https://www.plurk.com/OAuth/request_token');
	$signature_method = new SignatureMethod_HMAC_SHA1();
	$request->sign_request($signature_method, $this->consumer, $this->token);
	$header = $request->to_header();
	$gold = array ('Authorization' => 'OAuth realm="", oauth_consumer_key="con_key", oauth_token="auth_token", oauth_signature_method="HMAC_SHA1", oauth_signature="4QJdtxu30u/YhwTgexeStWxy6Ec="');
	$this->assertEquals($gold, $header);
    }

    public function testPOSTGetRequestToken2() {
	$request = Request::from_consumer_and_token(
	    $this->consumer, $this->token, "POST",
	    'https://www.plurk.com/OAuth/request_token');
	$signature_method = new SignatureMethod_HMAC_SHA1();
	$request->sign_request($signature_method, $this->consumer, $this->token);
	$header = $request->to_header();
	$gold = array ('Authorization' => 'OAuth realm="", oauth_consumer_key="con_key", oauth_token="auth_token", oauth_signature_method="HMAC_SHA1", oauth_signature="4QJdtxu30u/YhwTgexeStWxy6Ec="');
	$this->assertNotEquals($gold, $header);
    }
}
   
