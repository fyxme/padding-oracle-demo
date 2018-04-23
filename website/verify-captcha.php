<?php
include 'constants.php';

global $ret_msgs;

include 'tools.php';

$ciphertext = base64_decode($_GET["captcha-verification"]);

// get iv from ciphertext
$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$iv = substr($ciphertext, 0, $iv_size);
$ciphertext = substr($ciphertext, $iv_size);

$verification = aes128_cbc_decrypt($encryption_key, $ciphertext, $iv);


$attempt = $_GET["captcha-attempt"];
$name = $_GET["name"];
$email = $_GET["email"];
$password = $_GET["password"];

if ($attempt === $verification) {
    // redirect to vote.html
    redirect("http://localhost:8888/vote.html");
}

send_error($ret_msgs["invalid-attempt"]);
?>
