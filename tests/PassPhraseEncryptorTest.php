<?php

namespace Test\AlphaSoft\AsCrypto;

use AlphaSoft\AsCrypto\PassPhraseEncryptor;
use PHPUnit\Framework\TestCase;

class PassPhraseEncryptorTest extends TestCase
{
    public function testEncryptAndDecrypt()
    {
        $password = 'secret';
        $plaintext = 'Hello, world!';

        $encryptor = new PassPhraseEncryptor($password);
        $ciphertext = $encryptor->encrypt($plaintext);
        $decrypted = $encryptor->decrypt($ciphertext);

        $this->assertEquals($plaintext, $decrypted);
    }
}