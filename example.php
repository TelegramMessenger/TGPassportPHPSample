<?php

require_once 'config.php';

// Callback case
if ($_GET['set_ssid']) {
  list($ssid, $ssid_hash) = explode('_', $_GET['set_ssid'], 2);
  if ($ssid_hash !== hash_hmac('sha256', 'ssid'.$ssid, HMAC_SECRET)) {
    die('Invalid hmac hash');
  }
  setcookie('tg_ssid', $ssid, time() + 864000, '', '', true, true);
  if ($_GET['tg_passport'] == 'success') {
    $nonce = hash_hmac('sha256', 'nonce'.$ssid, HMAC_SECRET);
    $passport_data = [
      'pending' => time(),
    ];
    $MC->add('passport_data_'.$nonce, $passport_data);
  }
  $redirect_url = BASE_URL.'example.php';
  header('Location: '.$redirect_url);
  exit;
}

$ssid = $_COOKIE['tg_ssid'];
if (!$ssid) {
  // Generate ssid if not exists
  $ssid = bin2hex(openssl_random_pseudo_bytes(32));
  setcookie('tg_ssid', $ssid, time() + 864000, '', '', true, true);
}
$ssid_hash    = hash_hmac('sha256', 'ssid'.$ssid, HMAC_SECRET);
$nonce        = hash_hmac('sha256', 'nonce'.$ssid, HMAC_SECRET);
$callback_url = BASE_URL.'example.php?set_ssid='.$ssid.'_'.$ssid_hash;

// Logout case
if ($_GET['logout']) {
  setcookie('tg_ssid', '', 1, '', '', true, true);
  $MC->delete('passport_data_'.$nonce);

  $redirect_url = BASE_URL.'example.php';
  header('Location: '.$redirect_url);
  exit;
}

$passport_data = $MC->get('passport_data_'.$nonce);

if ($passport_data['pending']) {

  $html = <<<HTML
<h1>Hello, anonymous!</h1>
<br><h2 style="color:grey">Waiting for passport data...</h2><br>
<p><a href="?logout=1">Cancel</a></p>
HTML;
  $js = <<<JAVASCRIPT
setTimeout(function() {
  location.reload();
}, 1000);
JAVASCRIPT;

}
elseif ($passport_data && $passport_data['nonce'] == $nonce) {

  $tg_user    = $passport_data['user'];
  $first_name = htmlspecialchars($tg_user['first_name']);
  $last_name  = htmlspecialchars($tg_user['last_name']);
  if (isset($tg_user['username'])) {
    $username = htmlspecialchars($tg_user['username']);
    $html .= "<h1>Hello, <a href=\"https://t.me/{$username}\">{$first_name} {$last_name}</a>!</h1>";
  } else {
    $html .= "<h1>Hello, {$first_name} {$last_name}!</h1>";
  }
  if (isset($passport_data['data'])) {
    foreach ($passport_data['data'] as $password_value) {
      $type = $password_value['type'];
      $fields_html = '';
      if ($password_value['data']) {
        foreach ($password_value['data'] as $data_key => $data_val) {
          $data_key_html = htmlspecialchars($data_key);
          $data_val_html = htmlspecialchars($data_val);
          $fields_html .= <<<HTML
<dl>
  <dt>{$data_key_html}</dt>
  <dd>{$data_val_html}</dd>
</dl>
HTML;
        }
      }
      if ($password_value['front_side']) {
        $passport_file = $password_value['front_side'];
        $file_url      = htmlspecialchars($passport_file['file_url']);
        $fields_html .= <<<HTML
<dl>
  <dt>front_side</dt>
  <dd>
    <div class="files">
      <div class="file_item">
        <a href="{$file_url}" target="_blank"><img src="{$file_url}" /></a>
      <div>
    </div>
  </dd>
</dl>
HTML;
      }
      if ($password_value['reverse_side']) {
        $passport_file = $password_value['reverse_side'];
        $file_url      = htmlspecialchars($passport_file['file_url']);
        $fields_html .= <<<HTML
<dl>
  <dt>reverse_side</dt>
  <dd>
    <div class="files">
      <div class="file_item">
        <a href="{$file_url}" target="_blank"><img src="{$file_url}" /></a>
      <div>
    </div>
  </dd>
</dl>
HTML;
      }
      if ($password_value['selfie']) {
        $passport_file = $password_value['selfie'];
        $file_url      = htmlspecialchars($passport_file['file_url']);
        $fields_html .= <<<HTML
<dl>
  <dt>selfie</dt>
  <dd>
    <div class="files">
      <div class="file_item">
        <a href="{$file_url}" target="_blank"><img src="{$file_url}" /></a>
      <div>
    </div>
  </dd>
</dl>
HTML;
      }
      if ($password_value['files']) {
        $files_html = '';
        foreach ($password_value['files'] as $passport_file) {
          $file_url    = htmlspecialchars($passport_file['file_url']);
          $files_html .= <<<HTML
<div class="file_item">
  <a href="{$file_url}" target="_blank"><img src="{$file_url}" /></a>
<div>
HTML;
        }
        $fields_html .= <<<HTML
<dl>
  <dt>files</dt>
  <dd>
    <div class="files">{$files_html}</div>
  </dd>
</dl>
HTML;
      }
      if ($password_value['translation']) {
        $files_html = '';
        foreach ($password_value['translation'] as $passport_file) {
          $file_url    = htmlspecialchars($passport_file['file_url']);
          $files_html .= <<<HTML
<div class="file_item">
  <a href="{$file_url}" target="_blank"><img src="{$file_url}" /></a>
<div>
HTML;
        }
        $fields_html .= <<<HTML
<dl>
  <dt>translation</dt>
  <dd>
    <div class="files">{$files_html}</div>
  </dd>
</dl>
HTML;
      }
      if ($password_value['phone_number']) {
        $phone_number = htmlspecialchars($password_value['phone_number']);
        $fields_html .= <<<HTML
<dl>
  <dd>{$phone_number}</dd>
</dl>
HTML;
      }
      if ($password_value['email']) {
        $email = htmlspecialchars($password_value['email']);
        $fields_html .= <<<HTML
<dl>
  <dd>{$email}</dd>
</dl>
HTML;
      }
      $html .= <<<HTML
<fieldset>
  <legend>{$type}</legend>
  {$fields_html}
</fieldset>
HTML;
    }
  }
  $html .= "<p><a href=\"?logout=1\">Log out</a></p>";
}
else {
  $options_str = json_encode([
    'bot_id'       => BOT_ID,
    'scope'        => ['data' => [
      ['type' => 'personal_details', 'native_names' => true],
      ['type' => 'id_document', 'selfie' => true],
      'address',
      ['type' => 'address_document', 'translation' => true],
      'phone_number',
      'email'
    ], 'v' => 1],
    'public_key'   => BOT_PUBLIC_KEY,
    'nonce'        => $nonce,
    'callback_url' => $callback_url,
  ]);
  $html .= <<<HTML
<h1>Hello, anonymous!</h1>
<div id="auth_button"></div>
HTML;
  $js = <<<JAVASCRIPT
var auth_button = document.getElementById('auth_button');
Telegram.Passport.createAuthButton(auth_button, {$options_str});
JAVASCRIPT;
}


echo <<<HTML
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Telegram Passport Example</title>
    <style>
body {
  padding: 0;
  margin: 0 auto;
  font-size: 16px;
}
img {
  vertical-align: top;
  max-height: 150px;
}
.column {
  max-width: 420px;
}
fieldset {
  display: block;
  text-align: left;
  border: none;
  margin: 0 0 10px;
  max-width: 460px;
}
legend {
  padding: 0 3px;
  color: #999;
  font-weight: bold;
  width: 100%;
  box-sizing: border-box;
}
h3 {
  color: #999;
}
dt {
  width: 170px;
  float: left;
}
dt:after {
  content: ':';
}
dd {
  font-weight: bold;
  overflow: hidden;
  margin: 0;
}
dl {
  overflow: hidden;
  padding: 3px;
  margin: 2px 0;
}
input[type="text"] {
  font-family: sans-serif;
  vertical-align: top;
  font-size: 16px;
  padding: 4px 10px;
  width: 350px;
}
label {
  font-family: sans-serif;
  display: block;
  margin: 2px 0 7px;
}
.file_item {
  margin: 3px 0;
}
    </style>
    <script src="telegram-passport.js"></script>
  </head>
  <body><center>{$html}</center></body>
  <script>{$js}</script>
</html>
HTML;

?>
