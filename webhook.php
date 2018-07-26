<?php

require_once 'config.php';

$webhook_hash = hash_hmac('sha256', BOT_TOKEN, HMAC_SECRET);

if ($_GET['_set_webhook']) {
  // Open webhook.php?_set_webhook=1 to set up webhook
  $webhook_url = BASE_URL.'webhook.php?hash='.$webhook_hash;
  $result = botApiInvoke('setWebhook', [
    'url' => $webhook_url,
  ]);
  echo $result['ok'] ? 'Success' : 'Fail';
  exit;
}

if ($_GET['hash'] !== $webhook_hash) {
  // Invalid webhook url
  exit;
}

$raw_post_data = file_get_contents('php://input');
$update = json_decode($raw_post_data, true);

if (!isset($update['message']['passport_data'])) {
  // Supports passport_data update only
  exit;
}
$passport_data = $update['message']['passport_data'];

$credentials      = $passport_data['credentials'];
$secret_encrypted = base64_decode($credentials['secret']);
$result           = openssl_private_decrypt($secret_encrypted, $credentials_secret, BOT_PRIVATE_KEY, OPENSSL_PKCS1_OAEP_PADDING);
if (!$result) {
  // Credential secret decryption failed
  exit;
}

try {
  $credentials_data_encrypted = base64_decode($credentials['data']);
  $credentials_hash           = base64_decode($credentials['hash']);
  $credentials_data_json      = decryptData($credentials_data_encrypted, $credentials_secret, $credentials_hash);
  $credentials_data           = json_decode($credentials_data_json, true);

  if (!isset($credentials_data['secure_data']) ||
      !isset($credentials_data['payload'])) {
    throw new Exception('CREDENTIALS_FORMAT_INVALID');
  }
  $secure_data = $credentials_data['secure_data'];
  $payload     = $credentials_data['payload'];
  if (!preg_match('/^[0-9a-f]{64}$/', $payload)) {
    throw new Exception('PAYLOAD_INVALID');
  }

  foreach ($passport_data['data'] as &$passport_data_item) {
    $field_name = $passport_data_item['type'];
    if (isset($secure_data[$field_name])) {
      $secure_data_item = $secure_data[$field_name];
      if (isset($secure_data_item['data']) &&
          isset($passport_data_item['data'])) {
        $value_credentials = $secure_data_item['data'];
        $value_hash        = base64_decode($value_credentials['data_hash']);
        $value_secret      = base64_decode($value_credentials['secret']);
        $data_encrypted    = base64_decode($passport_data_item['data']);
        $value_data        = decryptData($data_encrypted, $value_secret, $value_hash);
        $value_data_json   = json_decode($value_data, true);
        $passport_data_item['data'] = $value_data_json;
      }
      if (isset($secure_data[$field_name]['front_side']) &&
          isset($passport_data_item['front_side'])) {
        $file_data      = $passport_data_item['front_side'];
        $file_id        = $file_data['file_id'];
        $file_encrypted = botApiGetFileContentsByFileId($file_id);
        if ($file_encrypted !== false) {
          $file_credentials = $secure_data[$field_name]['front_side'];
          $file_hash        = base64_decode($file_credentials['file_hash']);
          $file_secret      = base64_decode($file_credentials['secret']);
          $file_content     = decryptData($file_encrypted, $file_secret, $file_hash);
          $file_local_path  = md5($file_id).'.jpg';
          unset($file_data['file_path']);
          if (file_put_contents(FILES_DIR.$file_local_path, $file_content)) {
            $file_data['file_url'] = FILES_BASE_URL.$file_local_path;
          }
          $file_data['file_hash'] = $file_credentials['file_hash'];
          $passport_data_item['front_side'] = $file_data;
        }
      }
      if (isset($secure_data[$field_name]['reverse_side']) &&
          isset($passport_data_item['reverse_side'])) {
        $file_data      = $passport_data_item['reverse_side'];
        $file_id        = $file_data['file_id'];
        $file_encrypted = botApiGetFileContentsByFileId($file_id);
        if ($file_encrypted !== false) {
          $file_credentials = $secure_data[$field_name]['reverse_side'];
          $file_hash        = base64_decode($file_credentials['file_hash']);
          $file_secret      = base64_decode($file_credentials['secret']);
          $file_content     = decryptData($file_encrypted, $file_secret, $file_hash);
          $file_local_path  = md5($file_id).'.jpg';
          unset($file_data['file_path']);
          if (file_put_contents(FILES_DIR.$file_local_path, $file_content)) {
            $file_data['file_url'] = FILES_BASE_URL.$file_local_path;
          }
          $file_data['file_hash'] = $file_credentials['file_hash'];
          $passport_data_item['reverse_side'] = $file_data;
        }
      }
      if (isset($secure_data[$field_name]['selfie']) &&
          isset($passport_data_item['selfie'])) {
        $file_data      = $passport_data_item['selfie'];
        $file_id        = $file_data['file_id'];
        $file_encrypted = botApiGetFileContentsByFileId($file_id);
        if ($file_encrypted !== false) {
          $file_credentials = $secure_data[$field_name]['selfie'];
          $file_hash        = base64_decode($file_credentials['file_hash']);
          $file_secret      = base64_decode($file_credentials['secret']);
          $file_content     = decryptData($file_encrypted, $file_secret, $file_hash);
          $file_local_path  = md5($file_id).'.jpg';
          unset($file_data['file_path']);
          if (file_put_contents(FILES_DIR.$file_local_path, $file_content)) {
            $file_data['file_url'] = FILES_BASE_URL.$file_local_path;
          }
          $file_data['file_hash'] = $file_credentials['file_hash'];
          $passport_data_item['selfie'] = $file_data;
        }
      }
      if (isset($secure_data_item['files']) &&
          isset($passport_data_item['files'])) {
        foreach ($passport_data_item['files'] as $i => $file_data) {
          $file_id        = $file_data['file_id'];
          $file_encrypted = botApiGetFileContentsByFileId($file_id);
          if ($file_encrypted !== false) {
            $file_credentials = $secure_data_item['files'][$i];
            $file_hash        = base64_decode($file_credentials['file_hash']);
            $file_secret      = base64_decode($file_credentials['secret']);
            $file_content     = decryptData($file_encrypted, $file_secret, $file_hash);
            $file_local_path  = md5($file_id).'.jpg';
            unset($file_data['file_path']);
            if (file_put_contents(FILES_DIR.$file_local_path, $file_content)) {
              $file_data['file_url'] = FILES_BASE_URL.$file_local_path;
            }
            $file_data['file_hash'] = $file_credentials['file_hash'];
            $passport_data_item['files'][$i] = $file_data;
          }
        }
      }
    }
  }
} catch (Exception $e) {
  if (!isset($credentials_data['payload']) ||
      !preg_match('/^[0-9a-f]{64}$/', $credentials_data['payload'])) {
    // Payload invalid
    exit;
  }
  $payload = $credentials_data['payload'];
  $passport_data = [
    'error' => $e->getMessage(),
  ];
}

$passport_data['user'] = $update['message']['from'];
$passport_data['payload'] = $payload;

$MC->set('passport_data_'.$payload, $passport_data);
exit;


// Functions

function decryptData($data_encrypted, $data_secret, $data_hash) {
  $data_secret_hash = hash('sha512', $data_secret.$data_hash, true);
  $data_key         = substr($data_secret_hash, 0, 32);
  $data_iv          = substr($data_secret_hash, 32, 16);
  $options          = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
  $data_decrypted   = openssl_decrypt($data_encrypted, 'aes-256-cbc', $data_key, $options, $data_iv);
  if (!$data_decrypted) {
    throw new Exception('DECRYPT_FAILED');
  }
  $data_decrypted_hash = hash('sha256', $data_decrypted, true);
  if (strcmp($data_hash, $data_decrypted_hash)) {
    throw new Exception('HASH_INVALID');
  }
  $padding_len    = ord($data_decrypted[0]);
  $data_decrypted = substr($data_decrypted, $padding_len);
  return $data_decrypted;
}

function botApiInvoke($method, $params) {
  $api_url = 'https://api.telegram.org/bot'.BOT_TOKEN;
  $params_arr = [];
  foreach ($params as $key => $val) {
    if (!is_numeric($val) && !is_string($val)) {
      $val = json_encode($val);
    }
    $params_arr[] = rawurlencode($key).'='.rawurlencode($val);
  }
  $query_string = implode('&', $params_arr);

  $curl = curl_init();
  curl_setopt($curl, CURLOPT_URL, $api_url.'/'.$method);
  curl_setopt($curl, CURLOPT_POST, true);
  curl_setopt($curl, CURLOPT_POSTFIELDS, $query_string);
  curl_setopt($curl, CURLOPT_VERBOSE, true);
  curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 3);
  curl_setopt($curl, CURLOPT_TIMEOUT, 10);

  $response = curl_exec($curl);
  $errno = curl_errno($curl);
  $http_code = intval(curl_getinfo($curl, CURLINFO_HTTP_CODE));

  if ($http_code >= 400) {
    if ($http_code == 401) {
      throw new Exception('ACCESS_TOKEN_INVALID');
    }
    throw new Exception('HTTP_ERROR_'.$http_code);
  }
  if ($errno) {
    $error = curl_error($curl);
    throw new Exception('CURL_ERROR: '.$error);
  }

  $result = json_decode($response, true);
  if (!$result) {
    throw new Exception('RESPONSE_JSON_INVALID');
  }
  return $result;
}

function botApiGetFileContents($file) {
  $api_url = 'https://api.telegram.org/file/bot'.BOT_TOKEN;
  $file_path = $file['file_path'];

  $curl = curl_init();
  curl_setopt($curl, CURLOPT_URL, $api_url.'/'.$file_path);
  curl_setopt($curl, CURLOPT_HTTPGET, true);
  curl_setopt($curl, CURLOPT_VERBOSE, true);
  curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 3);
  curl_setopt($curl, CURLOPT_TIMEOUT, 10);

  $response = curl_exec($curl);
  $errno = curl_errno($curl);
  $http_code = intval(curl_getinfo($curl, CURLINFO_HTTP_CODE));

  if ($http_code >= 400) {
    if ($http_code == 401) {
      throw new Exception('ACCESS_TOKEN_INVALID');
    }
    throw new Exception('HTTP_ERROR_'.$http_code);
  }
  if ($errno) {
    $error = curl_error($curl);
    throw new Exception('CURL_ERROR: '.$error);
  }
  return $response;
}

function botApiGetFileContentsByFileId($file_id) {
  $response = botApiInvoke('getFile', ['file_id' => $file_id]);
  if (!$response['ok']) {
    return false;
  }
  $file = $response['result'];
  $file_bytes = botApiGetFileContents($file);
  return $file_bytes;
}

?>
