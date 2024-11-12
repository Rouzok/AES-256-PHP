<?php
function encrypt($string, $secret_iv, $public_key)
{
    $encrypt_method = "AES-256-CBC";
    $key = hash('sha256', $public_key);
    $iv = substr(hash('sha256', $secret_iv), 0, 16);

    $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
    $output =  base64_encode($output);
    return $output;
}

function decrypt($string, $secret_iv, $public_key)
{
    $encrypt_method = "AES-256-CBC";
    $key = hash('sha256', $public_key);
    $iv = substr(hash('sha256', $secret_iv), 0, 16);

    $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
    return $output;
}
$message = "Hello";
$public_key = "user_1";
$secret_iv = "132";

$encrypt_str = encrypt($message, $secret_iv, $public_key);
echo $encrypt_str . '\n';

$decrypt_str = decrypt($encrypt_str, $secret_iv, $public_key);
echo $decrypt_str;
