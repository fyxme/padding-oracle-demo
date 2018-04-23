<?php
$encryption_key = "awesome123";

function aes128_cbc_encrypt($key, $data, $iv) {
    if(16 !== strlen($key)) $key = hash('MD5', $key, true);
    if(16 !== strlen($iv)) $iv = hash('MD5', $iv, true);

    $data = pkcs7pad($data, 16);

    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
}

function aes128_cbc_decrypt($key, $data, $iv) {
    if(16 !== strlen($key)) $key = hash('MD5', $key, true);
    if(16 !== strlen($iv)) $iv = hash('MD5', $iv, true);

    $data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);

    $unpadded = pkcs7unpad($data, 16); // This is the oracle

    return $unpadded;
}


/**
 * Right-pads the data string with 1 to n bytes according to PKCS#7,
 * where n is the block size.
 * The size of the result is x times n, where x is at least 1.
 *
 * The version of PKCS#7 padding used is the one defined in RFC 5652 chapter 6.3.
 * This padding is identical to PKCS#5 padding for 8 byte block ciphers such as DES.
 *
 * @param string $plaintext the plaintext encoded as a string containing bytes
 * @param integer $blocksize the block size of the cipher in bytes
 * @return string the padded plaintext
 */
function pkcs7pad($plaintext, $blocksize)
{
    $padsize = $blocksize - (strlen($plaintext) % $blocksize);
    return $plaintext . str_repeat(chr($padsize), $padsize);
}

/**
 * Validates and unpads the padded plaintext according to PKCS#7.
 * The resulting plaintext will be 1 to n bytes smaller depending on the amount of padding,
 * where n is the block size.
 *
 * The user is required to make sure that plaintext and padding oracles do not apply,
 * for instance by providing integrity and authenticity to the IV and ciphertext using a HMAC.
 *
 * Note that errors during uppadding may occur if the integrity of the ciphertext
 * is not validated or if the key is incorrect. A wrong key, IV or ciphertext may all
 * lead to errors within this method.
 *
 * The version of PKCS#7 padding used is the one defined in RFC 5652 chapter 6.3.
 * This padding is identical to PKCS#5 padding for 8 byte block ciphers such as DES.
 *
 * @param string padded the padded plaintext encoded as a string containing bytes
 * @param integer $blocksize the block size of the cipher in bytes
 * @return string the unpadded plaintext
 * @throws Exception if the unpadding failed
 */
function pkcs7unpad($padded, $blocksize)
{
    global $ret_msgs;
    $l = strlen($padded);

    if ($l % $blocksize != 0)
    {
        send_error($ret_msgs["invalid-padding"]);
        // send_error("Padded plaintext cannot be divided by the block size");
        exit();
    }

    $padsize = ord($padded[$l - 1]);

    if ($padsize === 0)
    {
        send_error($ret_msgs["invalid-padding"]);
        // send_error("Zero padding found instead of PKCS#7 padding");
        exit();
    }

    if ($padsize > $blocksize)
    {
        send_error($ret_msgs["invalid-padding"]);
        // send_error("Incorrect amount of PKCS#7 padding for blocksize");
        exit();
    }

    // check the correctness of the padding bytes by counting the occurance
    $padding = substr($padded, -1 * $padsize);
    if (substr_count($padding, chr($padsize)) != $padsize)
    {
        send_error($ret_msgs["invalid-padding"]);
        // send_error("Invalid PKCS#7 padding encountered");
        exit();
    }

    if ($ret_msgs["invalid-padding"] === $ret_msgs["invalid-attempt"]) sleep(1);

    return substr($padded, 0, $l - $padsize);
}

function get_captcha_text($nc) {
    $characters=array_merge(range(0,9),range('A','Z'),range('a','z'));//creating combination of numbers & alphabets
    shuffle($characters);

    $captcha_text="";
    for($i=0;$i<$nc;$i++)
    {
        $captcha_text.=$characters[rand(0,count($characters)-1)];
    }
    return $captcha_text;
}

function get_captcha_image($captcha_text) {
    $captcha_image=imagecreatetruecolor(280,80);
    $captcha_background=imagecolorallocate($captcha_image,225,238,221);//setting captcha background colour
    $captcha_text_colour=imagecolorallocate($captcha_image,58,94,47);//setting cpatcha text colour

    imagefilledrectangle($captcha_image,0,0,280,79,$captcha_background);//creating the rectangle

    $font='fonts/a.ttf';

    imagettftext($captcha_image,30,0,50,50,$captcha_text_colour,$font,$captcha_text);
    ob_start();
    imagepng($captcha_image);
    $imagedata = ob_get_contents();
    ob_end_clean();
    return $imagedata;
}

function send_error($msg) {
    redirect('http://localhost:8888/register-get.php?msg='.urlencode($msg));
}

function redirect($url, $statusCode = 303)
{
   header('Location: ' . $url, true, $statusCode);
   die();
}

?>
