<?php

namespace AlphaSoft\AsCrypto;

final class PassPhraseEncryptor
{
    private AsCrypto $asCrypto;
    private string $password;

    /**
     * PassPhraseEncryptor constructor.
     *
     * @param string $password The password to use for encryption and decryption.
     * @param string $cipherMethod The cipher method to use. Defaults to 'aes-128-cbc'.
     * @throws \InvalidArgumentException If the cipher method is invalid.
     */
    public function __construct(string $password, string $cipherMethod = 'aes-128-cbc')
    {
        $this->password = $password;
        $this->asCrypto = new AsCrypto($cipherMethod);
    }

    /**
     * Encrypts the given plaintext using the stored password.
     *
     * @param string $plaintext The plaintext to encrypt.
     * @return string The encrypted ciphertext.
     * @throws \RuntimeException If encryption fails.
     */
    public function encrypt(string $plaintext): string
    {
        return $this->asCrypto->encrypt($plaintext, $this->password);
    }

    /**
     * Decrypts the given ciphertext using the stored password.
     *
     * @param string $ciphertextBase64 The base64 encoded ciphertext to decrypt.
     * @return string The decrypted plaintext.
     * @throws \RuntimeException If decryption fails.
     */
    public function decrypt(string $ciphertextBase64): string
    {
        return $this->asCrypto->decrypt($ciphertextBase64, $this->password);
    }
}