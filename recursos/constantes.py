""" Definición de valores constantes utilizados en el programa."""

import os

# --------------- Valores constantes ----------------
DB_PATH =       "outputs/secureyourmessage.db"  # Ruta a la base de datos SQLite
LOGS_PATH =     "outputs/logs.txt"              # Ruta al archivo de logs
OUTPUT_DIR =    "outputs"                       # Directorio de salida para archivos generados
AC1_CERT_FILE = os.path.join(OUTPUT_DIR, "AC1_cert.pem")
AC1_KEY_FILE  = os.path.join(OUTPUT_DIR, "AC1_key.pem.enc")
AC2_CERT_FILE = os.path.join(OUTPUT_DIR, "AC2_cert.pem")
AC2_KEY_FILE  = os.path.join(OUTPUT_DIR, "AC2_key.pem.enc")

SESSION_PRIV_KEYS = {}                           # Claves privadas en sesión (desbloqueadas)
KDF_ITERATIONS = 100_000                         # Número de iteraciones para PBKDF2
SALT_SIZE =      32                              # Tamaño de la sal en bytes

# -------------- Funciones auxiliares ---------------

def print_and_log(*args, **kwargs):
    """
    Función print que guarda en logs.txt las líneas de depuración.
    :param args:
    :param kwargs:
    :return:
    """
    line = " ".join(str(a) for a in args)       # Convertimos todo lo que se quiere imprimir en un string
    print(*args, **kwargs)                      # Print original        
    if line.startswith("["):                    # Guardamos líneas que empiezan con '['
        with open(LOGS_PATH, "a", encoding="utf-8") as f: 
            f.write(line + "\n")

def print_in_log(*args):
    """
    Función solo guarda en logs.txt las líneas de depuración.
    :param args:
    :param kwargs:
    :return:
    """
    line = " ".join(str(a) for a in args)       # Convertimos todo lo que se quiere imprimir en un string
    if line.startswith("["):                    # Guardamos líneas que empiezan con '['
        with open(LOGS_PATH, "a", encoding="utf-8") as f: 
            f.write(line + "\n")

def _to_bytes(x):
    """
    Convierte diferentes strings a bytes.
    :param x:
    :return:
    """
    if x is None:
        return None
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode()
    try:
        return memoryview(x).tobytes()
    except TypeError:
        raise
