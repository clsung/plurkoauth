<?

require('plurkAPI.php');

class PlurkAPITest extends PHPUnit_Framework_TestCase {
   
    protected $consumer_key;
    protected $consumer_secret;
    protected $oauth_token;
    protected $oauth_token_secret;
    protected $plurk;

    public function setUp(){
	$this->consumer_key = 'YOUR_CONSUMER_KEY';
	$this->consumer_secret = 'YOUR_CONSUMER_SECRET';
	$this->oauth_token = 'YOUR_ACCESS_TOKEN';
	$this->oauth_token_secret = 'YOUR_ACCESS_TOKEN_SECRET';
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
	$this->markTestSkipped("Due to oauth-php session incomplete, we need to skip it");
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
	$this->markTestSkipped("Due to oauth-php session incomplete, we need to skip it");
	$plurk = new PlurkAPI($this->consumer_key, $this->consumer_secret, 
	    $this->oauth_token, $this->oauth_token_secret
	);  
	$json = $plurk->callAPI('/APP/Profile/getOwnProfile');
	$this->assertNotNull($json);
	$this->assertEquals(0, $plurk->errno());
    }

}  
