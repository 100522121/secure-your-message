""" Aplicación de chat seguro entre el usuario y el bot 'Bob'."""

from database import init_db
from services import add_user, user_exists, verify_login, send_message, read_messages, ensure_bot_exists, create_chat

if __name__ == "__main__":
    init_db()                                       # Inicializar la base de datos
    
    print("\n=== 💬 Chat Seguro (Bot y Tú) ===")
    while True:
        username = input("Nombre de usuario: ").strip()     
        if username.lower() == "salir":
            print("Cerrando programa. ¡Hasta pronto!")
            exit(0)   
        password = input("Contraseña: ").strip()

        if not user_exists(username):
            add_user(username, password)
            break
        else:
            if verify_login(username, password):
                print(f"          💬 Bienvenido/a de nuevo, {username}.")
                break

    ensure_bot_exists()
    create_chat(username, "bob")

    print("\n--- Chat cifrado iniciado ---")
    print("(Escribe 'salir' para terminar)\n")

    while True:
        msg = input(f"{username}: ").strip()
        if not msg:                                 # Manejo de mensaje vacío
            print("Por favor, escribe algo antes de enviar.") 
            continue
        if msg.lower() == "salir":
            print("Cerrando chat. ¡Hasta pronto!")
            break
        # Envío del mensaje del usuario a Bob
        send_message(username, "bob", msg)

        # Respuestas predefinidas del bot
        if "hola" in msg.lower():
            reply = f"¡Hola {username}! Soy Bob 🤖."
        elif "como" in msg.lower() and "estas" in msg.lower():
            reply = "Todo en orden."
        else:
            reply = "Interesante... sigue contándome."

        send_message("bob", username, reply)
        read_messages(username, username, "bob")
        print("\n------------------------------\n")
