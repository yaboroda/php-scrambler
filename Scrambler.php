<?php

/**
 * cipher and decipher text string with checksum
 * same source string will be always ciphered into different code
 * @author yaboroda <yarboroda@gmail.com>
 */
class Scrambler
{
    private $hmacAlg = 'sha256';
    private $hmacLength = 32;
    private $cipher="AES-128-CBC";
    private $noiseLength=5;
    private $minKeyLength=16;
    private $key;
    private $ivLength;

    /**
     * to decipher message you'll need same $key
     * @param string $key
     */
    public function __construct($key)
    {
        if(strlen($key) < $this->minKeyLength){
            throw new \LengthException('chat_secret parameter should not be shorter then '.$this->minKeyLength);
        }
        $this->$key = $key;
        $this->ivLength = openssl_cipher_iv_length($this->cipher);
    }

    /**
     * cipher string
     * @param string $plainText
     * @return string
     */
    public function cipher($plainText)
    {
        $iv = openssl_random_pseudo_bytes($this->ivLength);
        $cipheredTextRaw = openssl_encrypt($plainText, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac($this->hmacAlg, $cipheredTextRaw, $this->key, TRUE);
        return base64_encode($this->getNoise().$iv.$hmac.$cipheredTextRaw);
    }

    /**
     * decipher string
     * @param string $message
     * @return string
     */
    public function decipher($message)
    {
        $cipher = substr(base64_decode($message), $this->noiseLength);
        $iv = substr($cipher, 0, $this->ivLength);
        $hmac = substr($cipher, $this->ivLength, $this->hmacLength);

        $cipheredTextRaw = substr($cipher, $this->ivLength+$this->hmacLength);
        $calcmac = hash_hmac($this->hmacAlg, $cipheredTextRaw, $this->key, TRUE);
        $originalPlainText = openssl_decrypt($cipheredTextRaw, $this->cipher, $this->key, $options=OPENSSL_RAW_DATA, $iv);

        if (hash_equals($hmac, $calcmac)){
            return $originalPlainText;
        }else{
            throw new \RuntimeException('Checksum does not match.');
        }
    }

    /**
     * get random bytes fixed length $this->noiseLength
     * @return string
     */
    protected function getNoise()
    {
        return openssl_random_pseudo_bytes($this->noiseLength);
    }
}
