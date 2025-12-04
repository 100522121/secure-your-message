""" Módulo de aplicación de chat seguro entre el usuario y el bot 'Bob'. """

from database import init_db
import pki  # Importamos el módulo unificado
from services import (
    add_user, user_exists, verify_login, unlock_private_key,
    send_message, read_messages, ensure_bot_exists, create_chat
)

if __name__ == "__main__":
    init_db()       # Inicializar base de Datos
    pki.init_pki()  # Inicializar PKI (Crea AC1 y AC2 si no existen)

    print("\n\n───────────────── SECURE YOUR MESSAGE ────────────────")
    print("\n--- Registro o inicio ---")
    # Menú inicial
    while True:
        action = input("Escribe 'registrar', 'iniciar' o 'salir': ").strip().lower()
        if action not in ("registrar", "iniciar", "salir"):
            print("Opción no válida.")
            continue
        
        if action == "salir":
            print("\nSaliendo de la aplicación. ¡Hasta pronto!\n")
            exit(0)

        print("")
        username = input("👋  Usuario: ").strip()
        password = input("🔑  Contraseña: ").strip()

        if action == "registrar":
            if user_exists(username):
                print(f"👤  El usuario '{username}' ya existe. Debes iniciar sesión.\n")
                continue

            # add_user crea las claves, guarda en BD y llama a pki.issue_certificate_for_user
            add_user(username, password)

            print("Usuario creado. Ahora debes iniciar sesión.\n")
            continue

        elif action == "iniciar":
            if not user_exists(username):
                print(f"👤 Usuario '{username}' no existe.\n")
                continue

            # verify_login verifica password y valida la cadena de certificados
            if verify_login(username, password):
                unlock_private_key(username, password)
                print(f"💬 Bienvenido/a, {username}.")
                break
            else:
                print("❌ Credenciales incorrectas o error de certificado.\n")
                continue

    # Asegurar que el bot exista y tenga certificado
    ensure_bot_exists()
    create_chat(username, "bob")

    while True:
        print("\n\n--- Nuevo mensaje ---")
        print("Escribe tu mensaje (o 'salir')\n")

        msg = input(f"{username} (Tú): ").strip()

        if not msg:
            print("Escribe algo.")
            continue

        if msg.lower() == "salir":
            print("Cerrando chat.\n")
            break
        
        send_message(username, "bob", msg)

        # Lógica simple del Bot
        if "hola" in msg.lower():
            reply = f"¡Hola, {username}! Soy Bob 🤖."
        elif "como" in msg.lower() and "estas" in msg.lower():
            reply = "Todo en orden, mis circuitos funcionan al 100%."
        else:
            reply = "Interesante... cuéntame más."

        send_message("bob", username, reply)
        read_messages(username, username, "bob")
