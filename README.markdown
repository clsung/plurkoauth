PlurkOAuth
======

PHP Wrapper of Plurk OAuth API

About
----
PlurkOAuth is a php wrapper for [Plurk API 2.0 beta](http://www.plurk.com/API/2)
You will need to [Sign Up](http://www.plurk.com/PlurkApp/register) for your own CUSTOMER TOKENs.

Prerequire Packages
----
[pecl_http](http://pecl.php.net/package/pecl_http), for http_build_url(), http_*.

[PHPUniut](http://www.phpunit.de) if you need test it (YOU SHOULD).

Example
----
% cp config.php.sample config.php # and modify it

``` php
require('plurkAPI.php');

$plurk = new PlurkAPI(CONSUMER_KEY, CONSUMER_SECRET,
    ACCESS_TOKEN, ACCESS_TOKEN_SECRET);
$json = $plurk->callAPI('/APP/Profile/getPublicProfile', array('user_id' => 'clsung'), true);
$json = $plurk->callAPI('/APP/Profile/getOwnProfile');
$json = $plurk->callAPI('/APP/FriendsFans/getFriendsByOffset', array ('user_id' => 'clsung'));
#$json = $plurk->callAPI('/APP/Timeline/getPlurks');
//$json = $plurk->callAPI('/APP/Timeline/plurkAdd', array ('content' => 'Post by plurkoauth which based on oauth-php', 'qualifier' => 'hates'));
```
