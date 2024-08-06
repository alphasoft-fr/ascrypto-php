<?php

namespace Test\AlphaSoft\AsCrypto;

use AlphaSoft\AsCrypto\AsCrypto;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

class AsCryptoTest extends TestCase
{

    /**
     * @throws RandomException
     */
    public function testEncryptDecrypt(): void
    {
        $crypto = new AsCrypto();
        $data = [];
        for ($i = 0; $i < 10; $i++) {
            $data[bin2hex(random_bytes(16))] = bin2hex(random_bytes(64));
        }

        $plaintext = json_encode($data);
        $password = uniqid();

        $ciphertext = $crypto->encrypt($plaintext, $password);
        $decrypted = $crypto->decrypt($ciphertext, $password);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDecryptInvalidCipherMethod(): void
    {
        $crypto = new AsCrypto();
        $ciphertext = 'invalid ciphertext';
        $password = 'mysecretpassword';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid cipher method');
        $crypto->decrypt($ciphertext, $password);
    }

    public function testDecryptInvalidPassword(): void
    {
        $crypto = new AsCrypto();
        $plaintext = 'Hello, world!';
        $password = 'mysecretpassword';

        $ciphertext = $crypto->encrypt($plaintext, $password);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Decryption failed');
        $crypto->decrypt($ciphertext, 'invalidpassword');
    }

}