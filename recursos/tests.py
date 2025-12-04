
""" Pruebas unitarias e integradas para los módulos 'cripto.py' y 'pki.py'.
Ejecutar este módulo con: python -m recursos.tests """

import unittest
import os
import shutil
import tempfile
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
import cripto
import pki
import recursos.constantes

# --- BLOQUE 1: Pruebas de Criptografía (Unit Testing) ---
class TestCryptoFunctions(unittest.TestCase):
    """ Pruebas unitarias para el módulo 'cripto.py'.
    Principio: Aislamiento. Probamos algoritmos sin efectos secundarios externos. """

    def setUp(self):
        """ Configuración previa a cada test. """
        # Generar par de claves RSA en memoria para pruebas rápidas
        self.priv_obj, self.pub_obj = cripto.generate_rsa_keypair()
        self.priv_pem, self.pub_pem = cripto.serialize_keys(self.priv_obj, self.pub_obj)
        
        # Datos base
        self.password = "TestPass_123!"
        self.message = "Mensaje secreto de prueba"

    # --- PBKDF2 (Hashing de contraseñas) ---
    def test_hash_password_structure(self):
        """ hash_password debe devolver salt y clave con longitud correcta (32 bytes). """
        salt, key = cripto.hash_password(self.password)
        self.assertEqual(len(salt), 32, "El Salt debería ser de 32 bytes")
        self.assertEqual(len(key), 32, "La clave derivada debería ser de 32 bytes (SHA-256)")

    def test_verify_password_logic(self):
        """ Verificar que la lógica de validación de contraseña funciona (Positivo y Negativo). """
        salt, key = cripto.hash_password(self.password)
        
        # Caso Positivo
        self.assertTrue(cripto.verify_password(salt, key, self.password))
        
        # Caso Negativo
        self.assertFalse(cripto.verify_password(salt, key, "WrongPass"))

    # --- AES-GCM (Simétrico) ---
    def test_aes_encryption_cycle(self):
        """ Ciclo completo: Generar clave -> Cifrar -> Descifrar. """
        aes_key = cripto.generate_aes_key()
        aad = b"header_data"
        
        # Cifrado
        enc_dict = cripto.encrypt_message(aes_key, self.message, aad)
        self.assertIn("ciphertext", enc_dict)
        self.assertIn("nonce", enc_dict)
        
        # Descifrado
        decrypted_msg = cripto.decrypt_message(aes_key, enc_dict)
        self.assertEqual(decrypted_msg, self.message)

    def test_aes_tampering(self):
        """ Principio de Integridad: Si se modifica el ciphertext, el descifrado debe fallar. """
        aes_key = cripto.generate_aes_key()
        enc_dict = cripto.encrypt_message(aes_key, self.message)
        
        # Corromper el último byte del texto cifrado
        original_ct = enc_dict["ciphertext"]
        tampered_ct = original_ct[:-1] + bytes([(original_ct[-1] + 1) % 256])
        enc_dict["ciphertext"] = tampered_ct
        
        with self.assertRaises(Exception):
            cripto.decrypt_message(aes_key, enc_dict)

    # --- RSA (Asimétrico) ---
    def test_rsa_encryption_flow(self):
        """ Cifrar con clave pública (simulada) y descifrar con privada. """
        # Simulamos el flujo: cifrar para usuario (usando su public key)
        # Nota: rsa_encrypt_for_user busca en DB, así que probamos la primitiva subyacente
        # o hacemos un mock. Aquí probaremos la primitiva directa para pureza unitaria.
        
        ciphertext = self.pub_obj.encrypt(
            self.message.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        plaintext = cripto.rsa_decrypt_with_privatekey(self.priv_obj, ciphertext)
        self.assertEqual(plaintext.decode(), self.message)

    def test_rsa_signature_flow(self):
        """ Firmar mensaje y verificar firma. """
        msg_bytes = self.message.encode()
        signature = cripto.sign_with_private_key_obj(self.priv_obj, msg_bytes)
        
        # Verificar firma válida
        is_valid = cripto.verify_signature_with_public_bytes(self.pub_pem, msg_bytes, signature, log=False)
        self.assertTrue(is_valid)

        # Verificar firma inválida (mensaje alterado)
        is_invalid = cripto.verify_signature_with_public_bytes(self.pub_pem, b"Mensaje Falso", signature, log=False)
        self.assertFalse(is_invalid)

    # --- Protección de Clave Privada ---
    def test_private_key_wrapping(self):
        """ Probar cifrado y descifrado de la clave privada (PEM) con contraseña. """
        encrypted_blob = cripto.encrypt_private_key_with_password(self.priv_pem, self.password)
        
        # Debe devolver bytes distintos al original
        self.assertNotEqual(encrypted_blob, self.priv_pem)
        
        # Descifrar
        decrypted_pem = cripto.decrypt_private_key_with_password(encrypted_blob, self.password)
        self.assertEqual(decrypted_pem, self.priv_pem)
        
        # Intentar cargarla para asegurar que no se corrompió
        serialization.load_pem_private_key(decrypted_pem, password=None)
    
    def test_decrypt_private_key_with_wrong_password(self):
        """ Intentar descifrar con contraseña errónea debe fallar. """
        password = "password_correcta"
        encrypted_blob = cripto.encrypt_private_key_with_password(self.priv_pem, password)
        with self.assertRaises(Exception):
            cripto.decrypt_private_key_with_password(encrypted_blob, "password_incorrecta")


# --- BLOQUE 2: Pruebas de PKI (Integration Testing con Mocks) ---
# Sustituye la clase TestPKIIntegration en tests.py por esta:

class TestPKIIntegration(unittest.TestCase):
    """ Pruebas para 'pki.py' en entorno efímero.
    Usamos carpetas temporales para no tocar los archivos reales. """

    def setUp(self):
        # Crear directorio temporal para certificados de prueba
        self.test_dir = tempfile.mkdtemp()
        
        # Definir rutas falsas dentro del directorio temporal
        self.fake_ac1_key = os.path.join(self.test_dir, "AC1_key.pem.enc")
        self.fake_ac1_cert = os.path.join(self.test_dir, "AC1_cert.pem")
        self.fake_ac2_key = os.path.join(self.test_dir, "AC2_key.pem.enc")
        self.fake_ac2_cert = os.path.join(self.test_dir, "AC2_cert.pem")

    def tearDown(self):
        # Limpiar directorio temporal al finalizar
        shutil.rmtree(self.test_dir)

    def test_init_pki_creates_files(self):
        """ init_pki debe crear los archivos AC1 y AC2 en el directorio configurado. """
        
        with patch('pki.OUTPUT_DIR', self.test_dir), \
             patch('recursos.constantes.AC1_KEY_FILE', self.fake_ac1_key), \
             patch('pki.AC1_CERT_FILE', self.fake_ac1_cert), \
             patch('recursos.constantes.AC2_KEY_FILE', self.fake_ac2_key), \
             patch('pki.AC2_CERT_FILE', self.fake_ac2_cert):
            
            pki.init_pki()
            
            self.assertTrue(os.path.exists(self.fake_ac1_key))
            self.assertTrue(os.path.exists(self.fake_ac2_cert))
            
            # Verificar validez básica
            with open(self.fake_ac2_cert, "rb") as f:
                ac2_cert_obj = x509.load_pem_x509_certificate(f.read())
            with open(self.fake_ac1_cert, "rb") as f:
                ac1_cert_obj = x509.load_pem_x509_certificate(f.read())
                
            try:
                ac1_cert_obj.public_key().verify(
                    ac2_cert_obj.signature,
                    ac2_cert_obj.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    ac2_cert_obj.signature_hash_algorithm
                )
            except Exception as e:
                self.fail(f"La firma de AC2 no es válida con la clave de AC1: {e}")

    # Parcheamos 'pki._get_user_row' porque pki.py lo importó a su namespace
    @patch('pki._get_user_row')     
    @patch('pki.add_certificate')   
    def test_issue_user_certificate(self, mock_add_cert, mock_get_user):
        """ issue_certificate_for_user debe generar un certificado válido firmado por AC2.
        Mockeamos la BD interceptando las llamadas dentro de pki.py. """
        # 1. Preparar entorno PKI (AC1 y AC2)
        with patch('pki.OUTPUT_DIR', self.test_dir), \
             patch('recursos.constantes.AC1_KEY_FILE', self.fake_ac1_key), \
             patch('pki.AC1_CERT_FILE', self.fake_ac1_cert), \
             patch('recursos.constantes.AC2_KEY_FILE', self.fake_ac2_key), \
             patch('pki.AC2_CERT_FILE', self.fake_ac2_cert):
            
            # Inicializamos PKI real en carpeta temporal
            pki.init_pki()

            # Preparar el Mock de la DB
            user_priv, user_pub = cripto.generate_rsa_keypair()
            _, user_pub_pem = cripto.serialize_keys(user_priv, user_pub)
            
            # Configuramos el mock para que devuelva el usuario falso
            mock_get_user.return_value = (1, b'fake_blob', user_pub_pem)

            # Ejecutar emisión
            username = "test_user"
            pki.issue_certificate_for_user(username)
            self.assertTrue(mock_add_cert.called, "add_certificate debería haber sido llamado")
            
            # Recuperar argumentos con los que se llamó a add_certificate
            args, _ = mock_add_cert.call_args
            cert_pem_arg = args[1]   # args[0] es username, args[1] es cert_pem
            is_chain_valid = pki.verify_certificate_chain(cert_pem_arg)   # 5. Verificar la cadena completa
            self.assertTrue(is_chain_valid, "La cadena Usuario -> AC2 -> AC1 debería ser válida")


if __name__ == "__main__":
    print("Ejecutando batería de pruebas...")
    unittest.main(verbosity=2)