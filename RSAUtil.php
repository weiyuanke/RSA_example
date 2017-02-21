<?php

/**
 * Created by PhpStorm.
 * User: weiyuanke
 * Date: 2017/2/7
 * Time: 上午9:57
 */
class RSAUtil
{
    private $private_key_str = '-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDP2SYzFccMwZxC05Uxwei6ijFcOoJOHPHBK2oRX6ZVDSZMxb7g
hH1HU63abxzcW/+OC845OlxC5XZA9AZtfgEHdYNpEGyaCHE1zu4LsWiovTLpYhV1
Ya9Ks/6ynUecn1P8D3OAKaCuD3DLlawLCRmWlc2EpnwYuJIrEf/OnB7A2QIDAQAB
AoGAEsWa9Jwv6RAHa+WuINtRiJ94i8rg/+sPTpH8N2t7G01fuylU7vQoWGvPVN4a
LjDE6PBaBMMnmAcfYghoGDV8JCWlgxza69JLG6BC/ug4AxKbPVN20okQSkXIRzKQ
2y+nyLk/ud2UJ5revYKv9Off/Byh6cFQJJMXTMB/SQNzJ4ECQQDqwP9T1i2EVMxo
GkYJWyYeKFcUFoHyjH+7cNitlMgd4f4+t7CpkiaXDNRu9nYuUC+T3KNJb/r1kuiQ
HUcZNVeRAkEA4qjGn3p/fmer0YruTX1X8xBIk0bgaKfnTAD8Mo/DvtzCu9L85m4P
y4DMDh9u40/TXeP5kvEh/XovRQedwO0AyQJBAL5WR28hO/yMiMNrchfJ6KkRCjGG
YkxXsIU45OYwuOTJxMvzQfDrSBC23VMuz/mTGFBp15cGjVMpjxiyNGBzCJECQBgA
f2gL9MxR9iPubmXOTC31H3pZGxJ6FUg7InnIN5ZSklyJbzaHmSyXqwQj1/5CScO7
jIY++rZ45eCNeesgLeECQFyzTM+ZcpJmD0gHrR9HOZVRGxuY4VEnlmXskmDofozU
62iHAnRxrSv8I1Fiafok33wS7QkLu3Zq4WqifNsmRwQ=
-----END RSA PRIVATE KEY-----';
    private $public_key_str = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP2SYzFccMwZxC05Uxwei6ijFc
OoJOHPHBK2oRX6ZVDSZMxb7ghH1HU63abxzcW/+OC845OlxC5XZA9AZtfgEHdYNp
EGyaCHE1zu4LsWiovTLpYhV1Ya9Ks/6ynUecn1P8D3OAKaCuD3DLlawLCRmWlc2E
pnwYuJIrEf/OnB7A2QIDAQAB
-----END PUBLIC KEY-----';
    private $pri_key;
    private $pub_key;

    function __construct()
    {
        $this->pub_key = openssl_pkey_get_public($this->public_key_str);
        $this->pri_key = openssl_pkey_get_private($this->private_key_str);
    }

    function encode_with_private($data)
    {
        $encrypted = false;
        openssl_private_encrypt($data,$encrypted,$this->pri_key);
        $encrypted = $this->urlsafe_b64encode($encrypted);
        return $encrypted;
    }

    function decode_with_public($encrypted)
    {
        $decrypted = false;
        openssl_public_decrypt($this->urlsafe_b64decode($encrypted), $decrypted, $this->pub_key);
        return $decrypted;
    }

    function encode_with_public($data)
    {
        $encrypted = false;
        openssl_public_encrypt($data,$encrypted,$this->pub_key);
        $encrypted = $this->urlsafe_b64encode($encrypted);
        return $encrypted;
    }

    function decode_with_private($encrypted)
    {
        $decrypted = false;
        openssl_private_decrypt($this->urlsafe_b64decode($encrypted), $decrypted, $this->pri_key);
        return $decrypted;
    }

    function urlsafe_b64encode($string)
    {
        $data = base64_encode($string);
//        $data = str_replace(array('+','/','='),array('-','_',''),$data);
        return $data;
    }

    function urlsafe_b64decode($string)
    {
//        $data = str_replace(array('-','_'),array('+','/'),$string);
//        $mod4 = strlen($data) % 4;
//        if ($mod4) {
//            $data .= substr('====', $mod4);
//        }
//        return base64_decode($data);
        return base64_decode($string);
    }
}

$rsa = new RSAUtil();
//$en = $rsa->encode_with_public('12345');
//error_log(json_encode($en));

$en = "t5ffhAZuzXPq1iAWbV7VgSzk1kdk2rgZ7pS1Hs6089u/rkRkhmBjnfv/Q+TfEGxuqwy+yhrmM5ylvUJqus9SxHdvqPGTUEIVEVw7TTbNnntde1sWmkX79ak//rsTVBPxejrLQsogaE/HLbY1BBmF+kr6I/Kfqz0I84ze1Yof56A=";
$de = $rsa->decode_with_private($en);
error_log(json_encode($de));
