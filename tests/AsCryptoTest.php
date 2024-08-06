<?php

namespace Test\AlphaSoft\AsCrypto;

use AlphaSoft\AsCrypto\AsCrypto;
use PHPUnit\Framework\TestCase;

class AsCryptoTest extends TestCase
{

    public function testEncryptDecrypt(): void
    {
        $crypto = new AsCrypto();
        $plaintext = bin2hex(random_bytes(128));
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