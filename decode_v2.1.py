import base64
import hashlib
import urllib.parse
import itertools
import string
import os
import random
import re
import subprocess
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Configuración de registro
logging.basicConfig(filename='security_tool_log.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Base de datos de hashes conocidos
hash_database = {
    '5d41402abc4b2a76b9719d911017c592': 'hello',                   # MD5
    '6dcd4ce23d88e2ee9568ba546c007c63': 'hello world',              # MD5
    '2c6ee24b09816a6f14f95d1698b24ead': 'password',                  # MD5
    'b94d27b9934d51d8e2b9b3bf6e5a53c2': '123456',                    # MD5
    'a71b8d9af9bc04d98f0a0c2e68b0c21a': 'admin123',                  # MD5
    '2bb80d537b1da3e38bd303eaa8e12c3e': 'SHA-1 example',            # SHA-1
    'c2c6b54d056d9e31efc3be0884594f4d': 'SHA-256 example',          # SHA-256
    'ddc9194c7875c8f0d52f6e1677cd49e8af183b4f5a862c7bdb981ac4ffb2f191b': 'Longer hash example', # SHA-512
}

def authenticate_user():
    """Función para autenticar al usuario."""
    correct_password = "admin123"
    attempts = 3
    for attempt in range(attempts):
        password = getpass("Ingrese la contraseña: ")
        if password == correct_password:
            print("Contraseña correcta.")
            otp_code = generate_otp()
            otp_input = input(f"Ingrese el código OTP: {otp_code}")
            if otp_input == otp_code:
                print("Autenticación exitosa.")
                return True
            else:
                print("Código OTP incorrecto.")
        else:
            print(f"Contraseña incorrecta. Intentos restantes: {attempts - (attempt + 1)}")
    print("Se ha superado el límite de intentos.")
    return False

def generate_otp():
    """Genera un código OTP (One Time Password)."""
    return ''.join(random.choices(string.digits, k=6))

def encrypt_aes(data, key):
    """Cifra datos usando AES-256."""
    key = hashlib.sha256(key.encode()).digest()
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), base64.b64encode(nonce).decode()

def decrypt_aes(encrypted_data, key, nonce):
    """Descifra datos cifrados con AES-256."""
    key = hashlib.sha256(key.encode()).digest()
    cipher = Cipher(algorithms.AES(key), modes.GCM(base64.b64decode(nonce)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
    return decrypted.decode()

def encrypt_chacha20(data, key):
    """Cifra datos usando ChaCha20-Poly1305."""
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode())
    return base64.b64encode(ciphertext).decode(), base64.b64encode(nonce).decode()

def decrypt_chacha20(encrypted_data, key, nonce):
    """Descifra datos usando ChaCha20-Poly1305."""
    cipher = Cipher(algorithms.ChaCha20(key, base64.b64decode(nonce)), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(base64.b64decode(encrypted_data))
    return decrypted.decode()

def generate_rsa_keys():
    """Genera claves RSA (4096 bits)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                                             encryption_algorithm=serialization.NoEncryption())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem.decode(), public_pem.decode()

def is_valid_hash(s):
    """Verifica si una cadena es un hash válido."""
    if re.match("^[a-f0-9]{32}$", s):
        return hashlib.md5
    elif re.match("^[a-f0-9]{40}$", s):
        return hashlib.sha1
    elif re.match("^[a-f0-9]{64}$", s):
        return hashlib.sha256
    elif re.match("^[a-f0-9]{128}$", s):
        return hashlib.sha512
    return None

def detect_hash_type(hash_value):
    if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value.lower()):
        return 'MD5'
    elif len(hash_value) == 40 and all(c in '0123456789abcdef' for c in hash_value.lower()):
        return 'SHA-1'
    elif len(hash_value) == 64 and all(c in '0123456789abcdef' for c in hash_value.lower()):
        return 'SHA-256'
    else:
        return None

def get_wordlist_for_hash(hash_type):
    wordlist_map = {
        'MD5':[
            '/bin/SecLists/Passwords/Common-Credentials/10k-most-common.txt',
            '/bin/SecLists/Passwords/darkc0de.txt',
            '/bin/SecLists/Passwords/rockyou.txt'
            ],
        'SHA-1':[
            '/bin/SecLists/Passwords/darkc0de.txt',
            '/bin/SecLists/Passwords/rockyou.txt'
            ],
        'SHA-256': [
            '/bin/SecLists/Passwords/Leaked-Databases/rockyou.txt',
            '/bin/SecLists/Passwords/weak-passwords.txt'
            ]
    }
    return wordlist_map.get(hash_type)




def get_default_wordlist_options():
    """Devuelve las opciones de diccionario predeterminadas disponibles."""
    return {
        '1': '/bin/SecLists/Passwords/Leaked-Databases/rockyou.txt',
        '2': '/bin/SecLists/Passwords/Common-Credentials/10k-most-common.txt', #1000-most-common-passwords.txt
        '3': '/bin/SecLists/Passwords/darkc0de.txt',
        '4': 'bin/SecLists/CommonCrawl_passwords.txt',
        '5': '/bin/SecLists/Passwords/Cracked-Hashes/milw0rm-dictionary.txt',
    }


def crack_hash(hash_value, wordlist):
    try:
        with open(wordlist, 'r', encoding='utf-8') as f:
            for line in f:
                password = line.strip()
                if hash_type == 'MD5' and hashlib.md5(password.encode()).hexdigest() == hash_value:
                    return password
                elif hash_type == 'SHA-1' and hashlib.sha1(password.encode()).hexdigest() == hash_value:
                    return password
                elif hash_type == 'SHA-256' and hashlib.sha256(password.encode()).hexdigest() == hash_value:
                    return password
    except Exception as e:
        print(f"Error al acceder o leer la wordlist: {e}")
    return None





def crack_hash_with_john(hash_value, mode='wordlist', wordlist=None):
    """Utiliza John the Ripper para crackear hashes."""
    with open("temp_hash.txt", "w") as f:
        f.write(hash_value + "\n")

    command = ['john']
    if mode == 'wordlist' and wordlist:
        command += ['--wordlist=' + wordlist]
    command.append('temp_hash.txt')

    try:
        subprocess.run(command, check=True)
        result = subprocess.run(['john', '--show', 'temp_hash.txt'], capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar John the Ripper: {e}")
        return None
    finally:
        os.remove("temp_hash.txt")

def brute_force_hash(target_hash, hash_type, max_length):
    """Realiza un ataque de fuerza bruta."""
    charset = string.ascii_letters + string.digits  # Puedes añadir caracteres especiales si lo deseas
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            candidate = ''.join(attempt)
            if hash_type(candidate.encode()).hexdigest() == target_hash:
                return candidate
    return None

def decode_base64(encoded_str):
    """Decodifica una cadena en Base64."""
    try:
        return base64.b64decode(encoded_str).decode('utf-8')
    except Exception:
        return None

def decode_hex(encoded_str):
    """Decodifica una cadena en Hexadecimal."""
    try:
        return bytes.fromhex(encoded_str).decode('utf-8')
    except Exception:
        return None

def decode_url(encoded_str):
    """Decodifica una cadena en URL."""
    return urllib.parse.unquote(encoded_str)

def decode_rot13(encoded_str):
    """Decodifica una cadena en ROT13."""
    return codecs.decode(encoded_str, 'rot_13')

def reverse_hash(hash_value):
    """Reversa un hash usando la base de datos de hashes conocidos."""
    return hash_database.get(hash_value)

def mostrar_menu():
    """Muestra el menú principal de la herramienta."""
    print("\nOpciones:")
    print("1. Decodificar Base64")
    print("2. Decodificar Hexadecimal")
    print("3. Decodificar URL")
    print("4. Decodificar ROT13")
    print("5. Verificar si es un hash")
    print("6. Realizar fuerza bruta en un hash (MD5, SHA1, SHA256, SHA512)")
    print("7. Realizar fuerza bruta en un hash con una wordlist personalizada")
    print("8. Cifrar una cadena (AES-256)")
    print("9. Descifrar una cadena cifrada (AES-256)")
    print("10. Cifrar una cadena (ChaCha20-Poly1305)")
    print("11. Descifrar una cadena cifrada (ChaCha20-Poly1305)")
    print("12. Generar claves RSA (4096 bits)")
    print("13. Limpiar la pantalla")
    print("14. Salir")

def clear_screen():
    """Limpiar la pantalla dependiendo del sistema operativo."""
    os.system("cls" if os.name == "nt" else "clear")

def main():
    """Función principal que inicia la herramienta de seguridad."""
    if not authenticate_user():
        return
    
    while True:
        try:
            mostrar_menu()
            choice = input("Seleccione una opción (1-14): ")

            if choice == '1':
                encoded_str = input("Ingrese una cadena codificada en Base64: ")
                decoded_str = decode_base64(encoded_str)
                print(f"Cadena decodificada: {decoded_str if decoded_str else 'No se pudo decodificar.'}")

            elif choice == '2':
                encoded_str = input("Ingrese una cadena codificada en Hexadecimal: ")
                decoded_str = decode_hex(encoded_str)
                print(f"Cadena decodificada: {decoded_str if decoded_str else 'No se pudo decodificar.'}")

            elif choice == '3':
                encoded_str = input("Ingrese una cadena codificada en URL: ")
                decoded_str = decode_url(encoded_str)
                print(f"Cadena decodificada: {decoded_str}")

            elif choice == '4':
                encoded_str = input("Ingrese una cadena codificada en ROT13: ")
                decoded_str = decode_rot13(encoded_str)
                print(f"Cadena decodificada: {decoded_str}")

            elif choice == '5':
                input_str = input("Ingrese una cadena para verificar si es un hash: ")
                hash_type = is_valid_hash(input_str)
                if hash_type:
                    print(f"La cadena es un hash {hash_type.__name__}.")
                    reversed_str = reverse_hash(input_str)
                    print(f"Valor revertido del hash: {reversed_str if reversed_str else 'No encontrado en la base de datos.'}")
                else:
                    print("La cadena no es un hash válido.")

            elif choice == '6':
                hash_value = input("Ingrese el hash para realizar fuerza bruta: ")
                hash_type = is_valid_hash(hash_value)
                max_length = int(input("Ingrese la longitud máxima de los intentos: "))  # Longitud ajustable
                if hash_type:
                    print(f"Intentando descifrar hash {hash_type.__name__}...")
                    original_input = brute_force_hash(hash_value, hash_type, max_length)
                    print(f"¡Contraseña encontrada! Es: {original_input}" if original_input else "No se pudo encontrar la contraseña.")
                else:
                    print("El hash no es compatible con la fuerza bruta.")

            elif choice == '7':
                hash_value = input("Ingrese el hash que desea crackear: ").strip()
                
                # Detectar el tipo de hash
                hash_type = detect_hash_type(hash_value)
                if hash_type is None:
                    print("Error: El hash ingresado no tiene un formato válido para MD5, SHA-1 o SHA-256.")
                    break  # Salir si el formato del hash no es válido

                print(f"Tipo de hash detectado: {hash_type}")

                # Obtener la wordlist adecuada según el tipo de hash
                selected_wordlist = get_wordlist_for_hash(hash_type)
                
                # Comprobar si la wordlist existe
                if not os.path.isfile(selected_wordlist):
                    print(f"Error: La wordlist para {hash_type} no se encuentra en la ruta especificada: {selected_wordlist}")
                    break  # Salir si la wordlist no existe

                # Intentar crackear el hash
                password_found = crack_hash(hash_value, selected_wordlist)

                if password_found:
                    print(f"¡Contraseña encontrada para {hash_type}! Es: {password_found.strip()}")
                else:
                    print(f"No se pudo encontrar la contraseña para {hash_type} en la wordlist seleccionada.")
            elif choice == '8':
                data = input("Ingrese el texto a cifrar (AES-256): ")
                key = getpass("Ingrese la clave (32 bytes): ")
                encrypted, nonce = encrypt_aes(data, key)
                print(f"Texto cifrado: {encrypted}\nNonce (para descifrado): {nonce}")

            elif choice == '9':
                encrypted_data = input("Ingrese el texto cifrado: ")
                key = getpass("Ingrese la clave de 32 bytes para AES-256: ")
                nonce = input("Ingrese el nonce: ")
                decrypted = decrypt_aes(encrypted_data, key, nonce)
                print(f"Texto descifrado: {decrypted}")

            elif choice == '10':
                data = input("Ingrese el texto a cifrar (ChaCha20): ")
                key = hashlib.sha256(getpass("Ingrese la clave (32 bytes para ChaCha20): ").encode()).digest()
                encrypted, nonce = encrypt_chacha20(data, key)
                print(f"Texto cifrado: {encrypted}\nNonce (para descifrado): {nonce}")

            elif choice == '11':
                encrypted_data = input("Ingrese el texto cifrado: ")
                key = hashlib.sha256(getpass("Ingrese la clave de 32 bytes para ChaCha20: ").encode()).digest()
                nonce = input("Ingrese el nonce: ")
                decrypted = decrypt_chacha20(encrypted_data, key, nonce)
                print(f"Texto descifrado: {decrypted}")

            elif choice == '12':
                private_key, public_key = generate_rsa_keys()
                print(f"Clave privada generada:\n{private_key}\n")
                print(f"Clave pública generada:\n{public_key}")

            elif choice == '13':
                clear_screen()

            elif choice == '14':
                print("Saliendo...")
                break

            else:
                print("Opción no válida.")

        except Exception as e:
            logging.error("Error en la opción seleccionada: %s", e)
            print("Se produjo un error, por favor intente nuevamente.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nPrograma cerrado por el usuario (Ctrl + C).")