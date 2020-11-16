<?php

/**
 * Class aflaCrypt
 */
class AflaCrypt
{

    protected $method;

    /**
     * AflaCrypt constructor.
     *
     * @param $method
     */
    public function __construct($method = 'aes-128-ccm')
    {

        $this -> method = $method;
        define('ENCRYPTION_KEY', 'c53272e65aa648609f82898c');
    }

    /**
     * @param string $string
     *
     * @return string
     */
    public function encrypt(string $string): string
    {

        $ivLen = openssl_cipher_iv_length($this -> method);
        $iv = openssl_random_pseudo_bytes($ivLen);
        $cipherTextRaw = openssl_encrypt($string, $this -> method, ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv);
        $hMac = hash_hmac('sha256', $cipherTextRaw, ENCRYPTION_KEY, true);

        return base64_encode($iv.$hMac.$cipherTextRaw);
    }

    /**
     * @param string $string
     *
     * @return bool|string
     */
    public function decrypt(string $string): string
    {

        $c = base64_decode($string);
        $ivLen = openssl_cipher_iv_length($this -> method);
        $iv = substr($c, 0, $ivLen);
        $hMac = substr($c, $ivLen, $sha2Len = 32);
        $cipherTextRaw = substr($c, $ivLen + $sha2Len);
        $plainText = openssl_decrypt($cipherTextRaw, $this -> method, ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv);
        $calcMac = hash_hmac('sha256', $cipherTextRaw, ENCRYPTION_KEY, true);

        return hash_equals($hMac, $calcMac) ? $plainText : '';
    }

    /**
     * @param string $url
     *
     * @return string
     */
    public function extractTokens(string $url): string
    {

        $tokens = substr($url, strpos($url, '?'));
        $tokens = str_replace('?', '', $tokens);
        $tokens = explode('&', $tokens);
        foreach ($tokens as $i => $token) $tokens[$i] = explode('=', $tokens[$i])[0];
        $tokens = implode('&', $tokens);

        return $tokens;
    }
}

$originalUrl = 'http://google.com?gclid={gclid}&placement={placement}&adposition={adposition}&campid={campaignid}&device={device}&devicemodel={devicemodel}&creative={creative}&adid={adid}&target={targetid}&keyword={keyword}&matchtype={matchtype}';
echo "original url:<br>$originalUrl<br><br>";
$afla = new AflaCrypt('AES-128-CBC');
$extractedTokens = $afla -> extractTokens($originalUrl);
echo 'extracted tokens: '.$extractedTokens.'<br><br>';
$encrypted = $afla -> encrypt($extractedTokens);
echo 'AES-128-CBC lenght: '.strlen($encrypted).'<br><br>encrypted: '.$encrypted.'<br><br>urlencoded: '.urlencode($encrypted);

echo '<br>decrypted: '.$afla -> decrypt($encrypted).'<br><br>';

echo '==============================================<br><br>';

$ciphers = openssl_get_cipher_methods();
foreach ($ciphers as $cipher) {
    $afla = new AflaCrypt($cipher);
    $extractedTokens = $afla -> extractTokens($originalUrl);
    $encrypted = $afla -> encrypt($extractedTokens);
    if (strlen($encrypted) <= 88) {
        echo $cipher.'<br>'.'lenght: '.strlen($encrypted).'<br>encrypted: '.$encrypted.'<br>';
        echo 'decrypted: '.$afla -> decrypt($encrypted).'<br><br>';
    }
}



















//echo "encrypted url:<br>http://google.com?8zjme={gclid}&mq8t9={placement}&9th8a={adposition}&6vi59={campaignid}&pwanp={device}&pwap5={devicemodel}&64alfw={creative}&9t91={adid}&buhs86={targetid}&1uxzk7e={keyword}&kwdu8v={matchtype}";

/*
//https://codernotes.ru/articles/php/obratimoe-shifrovanie-po-klyuchu-na-php.html
//https://pocketadmin.tech/ru/php-%D1%88%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5-%D0%B4%D0%B0%D0%BD%D0%BD%D1%8B%D1%85/