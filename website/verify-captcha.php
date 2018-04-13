<?php

include 'tools.php';


$ciphertext = base64_decode($_GET["captcha-verification"]);

// get iv from ciphertext
$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$iv = substr($ciphertext, 0, $iv_size);
$ciphertext = substr($ciphertext, $iv_size);

$verification = aes128_cbc_decrypt($encryption_key, $ciphertext, $iv);

echo "<br>";

$attempt = $_GET["captcha-attempt"];

//
// $a = $_GET["captcha-verification"];
// $b = $_GET["captcha-attempt"];

// $encrypted = aes128Encrypt($b, "abcd123");

if ($attempt === $verification) {
    echo "valid captcha";
    exit();
}

echo "invalid captcha";
?>
