from cryptography.fernet import Fernet
import json

# Genera una chiave e la salva in un file
def generate_key():
    key = Fernet.generate_key()
    with open("Huawei_Blackholing.key", "wb") as key_file:
        key_file.write(key)

# Carica la chiave
def load_key():
    return open("Huawei_Blackholing.key", "rb").read()

# Crittografa le credenziali e le salva in un file
def encrypt_credentials(router_ip, username, password):
    key = load_key()
    f = Fernet(key)
    credentials = {
        "router_ip": router_ip,
        "username": username,
        "password": password
    }
    encrypted_credentials = f.encrypt(json.dumps(credentials).encode())
    with open("Huawei_Blackholing.enc", "wb") as enc_file:
        enc_file.write(encrypted_credentials)

if __name__ == "__main__":
    generate_key()
    router_ip = input("Inserisci l'IP del router: ")
    username = input("Inserisci lo username: ")
    password = input("Inserisci la password: ")
    encrypt_credentials(router_ip, username, password)
    print("Credenziali crittografate salvate in 'Huawei_Blackholing.enc' e chiave salvata in 'Huawei_Blackholing.key'")
