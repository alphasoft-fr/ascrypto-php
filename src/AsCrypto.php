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
        $iv = openssl_random_pseudo_bytes($ivSize);

        $key = $this->generateKey($password, $iv);

        $ciphertext = openssl_encrypt($plaintext, $this->cipherMethod, $key, 0, $iv);
        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed');
        }

        return $this->cipherMethod . ';'. base64_encode(sprintf('%s%s', $iv, $ciphertext));
    }


    /**
     * Decrypts the given ciphertext using the provided password.
     *
     * @param string $ciphertextBase64 The base64 encoded ciphertext to decrypt.
     * @param string $password The password to use for decryption.
     * @return string The decrypted plaintext.
     * @throws \InvalidArgumentException If the cipher method is invalid.
     */
    public function decrypt(string $ciphertextBase64, string $password): string
    {
        [$cipherMethod, $textBase64] = explode(';', $ciphertextBase64, 2) + [null, null];
        if (!in_array($cipherMethod, openssl_get_cipher_methods())) {
            throw new \InvalidArgumentException('Invalid cipher method');
        }

        $textBase64 = explode(';', $ciphertextBase64)[1] ?? null;
        $ciphertextDecoded = base64_decode($textBase64);

        $ivSize = openssl_cipher_iv_length($cipherMethod);
        $iv = substr($ciphertextDecoded, 0, $ivSize);
        $ciphertext = substr($ciphertextDecoded, $ivSize);

        $key = $this->generateKey($password, $iv);

        $value = openssl_decrypt($ciphertext, $cipherMethod, $key, 0, $iv);
        if ($value === false) {
            throw new \RuntimeException('Decryption failed');
        }

        return $value;
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
        return hash_pbkdf2('sha256', $password, $iv, 10000, 32, true);
    }
}