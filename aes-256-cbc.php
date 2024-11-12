<?php
class Cipher
{
    private $encrypt_method = "AES-256-CBC";
    private $cipher_key;

    function __construct($encrypt_key = false)
    {
        if ($cipher_key = hex2bin($encrypt_key)) {
            $this->cipher_key = $cipher_key;
        } else {
            echo "Please insert encryption key";
        }
    }

    function encrypt($message)
    {
        $iv_size = openssl_cipher_iv_length($this->encrypt_method);
        $random_key = hash('sha256', $this->cipher_key);
        $new_iv = substr(hash('sha256', $random_key), 0, $iv_size);

        if ($encrypted = base64_encode(openssl_encrypt($message, $this->encrypt_method, $this->cipher_key, 0, $new_iv))) {
            return $new_iv . ':' . $encrypted;
        }
        return false;
    }

    function decrypt($message)
    {
        $arr = explode(":", $message);
        $iv = $arr[0];
        $key = $arr[1];

        if ($decrypt_message = openssl_decrypt(base64_decode($key), $this->encrypt_method, $this->cipher_key, 0, $iv)) {
            return $decrypt_message;
        }
        return false;
    }
}

// Encrypt Ussage

$message = "Hello AES-256";
$encrypt_key = bin2hex(substr(hash('sha256', random_bytes(16)), 0, 16));

$cipher = new Cipher($encrypt_key);
// Encrypt
$encrypted_message = $cipher->encrypt($message);
echo $encrypted_message;

echo "\n";

// Decrypt
$decrypted_message = $cipher->decrypt($encrypted_message);
echo $decrypted_message;
