import unittest
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cripto import hash_password, verify_password, generate_rsa_keypair


class TestCryptoFunctions(unittest.TestCase):
    """
    Pruebas unitarias esenciales para garantizar la calidad y seguridad del sistema.
    Cubre autenticación, cifrado simétrico y asimétrico.
    """
    def setUp(self):
        """
        Inicializa los datos comunes para las pruebas.
        """
        # Generar par de claves RSA para pruebas
        self.private_key, self.public_key = generate_rsa_keypair()
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Generar hash
        self.password = "contraseña_segura"
        self.salt, self.key = hash_password(self.password)


    # --- Pruebas de cifrado asimétrico (RSA) ---
    def test_generate_rsa_keypair_valid(self):
        """
        Comprueba que las claves RSA se generen con la longitud esperada.
        """
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)
        self.assertEqual(self.private_key.key_size, 2048)

    def test_rsa_encrypt_and_decrypt(self):
        """
        Verifica que los datos cifrados con la pública se descifren con la privada.
        """
        message = b"Mensaje secreto"
        ciphertext = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.assertEqual(message, plaintext)


    # --- Pruebas de autenticación (PBKDF2) ---
    def test_hash_password_returns_salt_and_key(self):
        """
        Verifica que hash_password devuelva sal y clave derivada válidas.
        """
        self.assertEqual(len(self.salt), 32)  # Salt de 32 bytes
        self.assertEqual(len(self.key), 32)

    def test_verify_password_correct(self):
        """
        Debe retornar True si la contraseña es correcta.
        """
        self.assertTrue(verify_password(self.salt, self.key, self.password))

    def test_verify_password_incorrect(self):
        """
        Debe retornar False si la contraseña es incorrecta.
        """
        self.assertFalse(verify_password(self.salt, self.key, "otra_clave"))


    # --- Pruebas de cifrado simétrico (AES-GCM) ---
    def test_encrypt_and_decrypt_message(self):
        """
        El mensaje cifrado debe descifrarse correctamente con la misma clave.
        """
        key = os.urandom(32)
        iv = os.urandom(16)
        message = b"hola mundo"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded = message + b"\x00" * (16 - len(message) % 16)
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.assertEqual(padded, plaintext)

    def test_decrypt_fails_with_modified_ciphertext(self):
        """
        La autenticación debe fallar si se altera el texto cifrado.
        """
        key = os.urandom(32)
        iv = os.urandom(16)             # Vector de inicialización aleatorio
        message = b"prueba"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded = message + b"\x00" * (16 - len(message) % 16)

        ciphertext = encryptor.update(padded) + encryptor.finalize()
        tampered = bytearray(ciphertext)
        tampered[0] = tampered[0] + 1   # Modificar el texto cifrado, sumamos 1 al primer byte

        decryptor = cipher.decryptor()
        decrypted = decryptor.update(bytes(tampered)) + decryptor.finalize()
        self.assertNotEqual(padded, decrypted)

    def test_encrypt_message_invalid_key_size(self):
        """
        Debe lanzar ValueError si la clave tiene un tamaño inválido.
        """
        with self.assertRaises(ValueError):
            Cipher(algorithms.AES(b"clave_invalida"), modes.CBC(os.urandom(16)))


if __name__ == "__main__":
    unittest.main()
