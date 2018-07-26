<?php

define('BOT_ID',          'XXXXXX');                              // place id of your bot here
define('BOT_USERNAME',    'XXXXXXXXXX');                          // place username of your bot here
define('BOT_TOKEN',       'XXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXX');   // place bot token of your bot here, KEEP IT SECRET!

define('BOT_PUBLIC_KEY',  '-----BEGIN PUBLIC KEY----- ...');      // place public key of your bot here
define('BOT_PRIVATE_KEY', '-----BEGIN RSA PRIVATE KEY----- ...'); // place private key of your bot here, KEEP IT SECRET!

define('HMAC_SECRET',     'XXXXXXXXXXXXXXXXXXXXXXXX');            // some random string for hmac secret

define('BASE_URL',        'https://example.com/passport/');       // place base url of your example page
define('FILES_BASE_URL',  'https://example.com/files/');          // place base url of saved files
define('FILES_DIR',       '/var/www/files/');                     // place dir where files are located

$MC = new Memcache;
$MC->connect('localhost', 11211);

?>
