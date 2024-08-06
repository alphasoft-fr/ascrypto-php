<?php

namespace AlphaSoft\AsCrypto;

/**
 * Class AsCrypto
 *
 * This class provides methods for encrypting and decrypting data using a password.
 */
final class AsCrypto
{
    /**
     * @var string The cipher method used for encryption and decryption.
     */
    private string $cipherMethod;
    private int $pbkdf2Iterations;

    /**
     * AsCrypto constructor.
     *
     * @param string $cipherMethod The cipher method to use. Defaults to 'aes-128-cbc'.
     * @throws \InvalidArgumentException If the cipher method is invalid.
     */
    public function __construct(string $cipherMethod = 'aes-128-cbc')
    {
        $cipherMethod = mb_strtolower($cipherMethod);
        if (!in_array($cipherMethod, openssl_get_cipher_methods())) {
            throw new \InvalidArgumentException('Invalid cipher method');
        }

        $this->cipherMethod = $cipherMethod;
    }

    /**
     * Encrypts the given plaintext using the provided password.
     *
     * @param string $plaintext The plaintext to encrypt.
     * @param string $password The password to use for encryption.
     * @return string The encrypted ciphertext.
     * @throws \RuntimeException If encryption fails.
     */
    public function encrypt(string $plaintext, string $password): string
    {
        $ivSize = openssl_cipher_iv_length($this->cipherMethod);
        if ($ivSize < 1) {
            $iv = '';
        }else {
            $iv = openssl_random_pseudo_bytes($ivSize);
        }

        $key = $this->generateKey($password, $iv);

        $ciphertext = openssl_encrypt(gzcompress($plaintext), $this->cipherMethod, $key, OPENSSL_RAW_DATA, $iv);
        if (!$ciphertext) {
            throw new \RuntimeException('Encryption failed');
        }

        $hmac = hash_hmac('sha256', $ciphertext, $key);
        return sprintf('%s;%s;%s', $this->cipherMethod, $hmac, base64_encode($iv.$ciphertext));
    }


    /**
     * Decrypts the given ciphertext using the provided password.
     *
     * @param string $encryptedText The base64 encoded ciphertext to decrypt.
     * @param string $password The password to use for decryption.
     * @return string The decrypted plaintext.
     * @throws \InvalidArgumentException If the cipher method is invalid.
     */
    public function decrypt(string $encryptedText, string $password): string
    {
        [$cipherMethod, $hmac, $textBase64] = explode(';', $encryptedText, 3) + [null, null, null];
        if (!in_array($cipherMethod, openssl_get_cipher_methods())) {
            throw new \InvalidArgumentException('Invalid cipher method');
        }

        $ciphertextDecoded = base64_decode($textBase64);

        $ivSize = openssl_cipher_iv_length($cipherMethod);
        $iv = substr($ciphertextDecoded, 0, $ivSize);
        $ciphertext = substr($ciphertextDecoded, $ivSize);

        $key = $this->generateKey($password, $iv);
        if (!hash_equals($hmac, hash_hmac('sha256', $ciphertext, $key))) {
            throw new \RuntimeException('Decryption failed');
        }

        $plaintext = openssl_decrypt($ciphertext, $cipherMethod, $key, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) {
            throw new \RuntimeException('Decryption failed');
        }

        return gzuncompress($plaintext);
    }

    /**
     * Generates a key using the provided password and initialization vector.
     *
     * @param string $password The password to use.
     * @param string $iv The initialization vector.
     * @return string The generated key.
     */
    private function generateKey(string $password, string $iv): string
    {
        return openssl_pbkdf2($password, $iv, 32, 1000, 'sha256');
    }
}