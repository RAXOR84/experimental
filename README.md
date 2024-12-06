# Herramienta de Seguridad Open Source para Bug Hunters

Esta herramienta es un conjunto de utilidades diseñadas para Bug Hunters y profesionales de la ciberseguridad, permitiendo el análisis, cracking de hashes, cifrado, y otras funcionalidades para pruebas de penetración y auditoría. El proyecto es open source, lo que permite su personalización y expansión para la captura de patrocinadores en el mercado comercial.

## Funcionalidades Principales

1. **Autenticación de Usuario**:  
   Utiliza autenticación de doble factor (contraseña + OTP) para asegurar el acceso.

2. **Cracking de Hashes**:
   - Detecta hashes MD5, SHA-1, SHA-256 y SHA-512.
   - Realiza ataques de fuerza bruta y cracking utilizando diccionarios preconfigurados.

3. **Cifrado/Descifrado**:
   - Soporta cifrado/descifrado con AES-256 y ChaCha20-Poly1305.
  
4. **Generación de Claves RSA**:
   - Genera claves RSA de 4096 bits para criptografía asimétrica.

5. **Decodificación de Cadenas**:
   - Permite la decodificación de Base64, Hexadecimal, URL y ROT13.

6. **Gestión de Hashes Conocidos**:
   - Proporciona una base de datos interna de hashes comunes, ayudando en la reversión rápida de contraseñas.

## Requisitos

- Python 3.6 o superior
- Bibliotecas necesarias:
  - cryptography
  - subprocess
  - itertools
  - hashlib
  - getpass
  - re
  - os
  - random
  - codecs

## Instalación

1. **Clona el repositorio**:

   ```bash
   git clone https://github.com/tu_usuario/herramienta-de-seguridad.git
   cd herramienta-de-seguridad


2.

   pip install -r requirements.txt

3.
  python3 security_tool.py



Uso
Autenticación: Inicia sesión con una contraseña y un código OTP (código generado automáticamente).  
Contraseña: admin123
Menú Principal: El menú ofrece diversas opciones para cifrar, descifrar, y analizar datos.
Cracking de Hashes: Utiliza la función de "fuerza bruta" o un diccionario de contraseñas para crackear hashes conocidos.
Cifrado de Datos: Permite cifrar datos con los algoritmos AES-256 y ChaCha20.
Generación de Claves RSA: Genera pares de claves RSA de 4096 bits para criptografía asimétrica.


Crecimiento y Uso Comercial
Este proyecto es ideal para la comunidad open source de ciberseguridad. Su expansión podría incluir:

Mejoras en la base de datos de hashes.
Adición de más algoritmos de cifrado.
Inclusión de más métodos de autenticación y mayor seguridad.
Integración de patrocinadores en el código mediante donaciones o suscripciones premium.
