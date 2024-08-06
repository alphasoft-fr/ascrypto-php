# ASCrypto

ASCrypto is a PHP encryption library providing a simple and secure solution for encrypting and decrypting data solely with a password. This library does not require additional key management.

## Installation

To install ASCrypto:

```bash
composer require alphasoft-fr/ascrypto-php
```

### Encryption

To encrypt data, use the `encrypt` method:

```php
$plaintext = 'Text to encrypt';
$password = 'secure_password';

$crypto = new AsCrypto();
$ciphertext = $crypto->encrypt($plaintext, $password);
echo $ciphertext;
```

### Decryption

To decrypt data, use the `decrypt` method:

```php
$ciphertext = 'Encrypted text to decrypt';
$password = 'secure_password';

$crypto = new AsCrypto();
$plaintext = $crypto->decrypt($ciphertext, $password);
echo $plaintext;
```

## Security

- **Cipher Method**: The default method is `aes-128-cbc`. Ensure that the method used meets your security requirements.
- **Key Management**: The library uses PBKDF2 to derive the encryption key from the password, avoiding the need for direct key management.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE](LICENSE) file for details.

---

# ASCrypto

ASCrypto est une bibliothèque de cryptage en PHP offrant une solution simple et sécurisée pour chiffrer et déchiffrer des données uniquement avec un mot de passe. Cette bibliothèque ne nécessite pas de gestion de clés supplémentaires.

## Installation

Pour installer ASCrypto :

```bash
composer require alphasoft-fr/ascrypto-php
```

### Chiffrement

Pour chiffrer des données, utilisez la méthode `encrypt` :

```php
$plaintext = 'Texte à chiffrer';
$password = 'mot_de_passe_securise';

$crypto = new AsCrypto();
$ciphertext = $crypto->encrypt($plaintext, $password);
echo $ciphertext;
```

### Déchiffrement

Pour déchiffrer des données, utilisez la méthode `decrypt` :

```php
$ciphertext = 'Texte chiffré à déchiffrer';
$password = 'mot_de_passe_securise';

$crypto = new AsCrypto();
$plaintext = $crypto->decrypt($ciphertext, $password);
echo $plaintext;
```

## Sécurité

- **Méthode de Chiffrement** : La méthode par défaut est `aes-128-cbc`. Assurez-vous que la méthode utilisée est appropriée pour vos besoins de sécurité.
- **Gestion des Clés** : La bibliothèque utilise PBKDF2 pour dériver la clé de chiffrement à partir du mot de passe, évitant ainsi la nécessité de gérer des clés directement.

## Licence

Ce projet est sous la licence [MIT](https://opensource.org/licenses/MIT). Voir le fichier [LICENSE](LICENSE) pour plus de détails.
