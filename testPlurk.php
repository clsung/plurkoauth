<?

require('plurkAPI.php');
require('config.php');

class PlurkAPITest extends PHPUnit_Framework_TestCase {
   
    protected $consumer_key;
    protected $consumer_secret;
    protected $oauth_token;
    protected $oauth_token_secret;
    protected $plurk;

    public function setUp(){
	$this->consumer_key = CONSUMER_KEY;
	$this->consumer_secret = CONSUMER_SECRET;
	$this->oauth_token = ACCESS_TOKEN;
	$this->oauth_token_secret = ACCESS_TOKEN_SECRET;
    } 

    public function tearDown(){}

    /**
     * @expectedException InvalidArgumentException
     */
    public function testNoConsumerKey()  
    {  
	$plurk = new PlurkAPI();  
    }  

    public function testInvalidConsumerKey()  
    {  
	$plurk = new PlurkAPI("abc", "def");  
	$json = $plurk->callAPI('/APP/Profile/getPublicProfile',
	    array('user_id' => 'clsung'), true);
	$this->assertNull($json);
	$this->assertContains('40101:unknown application key', $plurk->error());
    }  

    public function testValidConsumerKey()
    {
	$plurk = new PlurkAPI($this->consumer_key, $this->consumer_secret);  
	$json = $plurk->callAPI('/APP/Profile/getPublicProfile', array('user_id' => 'clsung'), true);
	$this->assertNotNull($json);
	$this->assertEquals(0, $plurk->errno());
    }

    /**
     * @depends testValidConsumerKey
     */
    public function testGetOwnProfile()
    {
	$plurk = new PlurkAPI($this->consumer_key, $this->consumer_secret, 
	    $this->oauth_token, $this->oauth_token_secret
	);  
	$json = $plurk->callAPI('/APP/Profile/getOwnProfile');
	$this->assertNotNull($json);
	$this->assertEquals(0, $plurk->errno());
    }

}  
