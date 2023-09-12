import sys
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import re
from Crypto.Hash import SHA256

def get_master_password(print_warning=True):
    master_password = ""
    special_char_check = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
    if print_warning == False:
        master_password = input("Enter your master password: ")
        return master_password
    while len(master_password) < 8 or not any(c.isupper() for c in master_password) or not special_char_check.search(master_password):
        master_password = input("Enter your master password: ")
        if (len(master_password) < 8 or not any(c.isupper() for c in master_password) or not special_char_check.search(master_password)) and print_warning:
            print("Master password size should be at least 8 characters long, contain at least one uppercase letter, and at least one special character!")
    return master_password

def init(master_password):
    key_salt = get_random_bytes(16) #sol za master pass
    key = scrypt(master_password.encode(), key_salt, 32, N=2**14, r=8, p=1) #generiraj kljuc 32B iz soli i master passa
    with open('key_salt.txt', 'wb') as file: #u key_salt drzim sol za master pass
        file.write(key_salt)
    salt = get_random_bytes(16)
    with open('passwords.txt', 'w') as file:
        file.write(encrypt("", key, salt)) #encryptam prazan string koji cu koristiti kao provjeru za master pass

def put(master_password, address, password):
    with open('key_salt.txt', 'rb') as file:
        key_salt = file.read()
    key = scrypt(master_password.encode(), key_salt, 32, N=2**14, r=8, p=1) #key iz master passa i njegove soli

    with open('passwords.txt', 'r') as file:
        lines = file.readlines() #svi retci iz passwords.txt

    new_lines = []
    found = False #zastavica ako novi zapis ima istu adresu
    if lines:
        for line in lines:
            line = line.strip()
            entry_salt, decrypted_data, success, dataTamper = decrypt(line, key) #svaku linije decryptam, dobijem njezinu sol, podatke i bool vrijednost o uspjehu
            if dataTamper == True:
                print("Warning: The data has been tampered with!")
                sys.exit(1)
            if success == False: #ako je decryption failao onda znaci da je master sifra kriva
                print("Incorrect master password!")
                sys.exit(1)
            if decrypted_data:  #provjeri jel postoje neki podatci
                entry_address, entry_password = decrypted_data.split(':', 1) #iz podataka izvuci adresu i sifru, odvojeni su dvotockom
                if entry_address == address: #ako azuriramo lozinku za neku adresu
                    found = True #postavi zastavicu nasli smo istu adresu
                    salt = get_random_bytes(16)
                    encrypted_data = encrypt(address + ":" + password, key, salt) #generiram novu sol za taj zapis i encryptam ga
                    new_lines.append(encrypted_data + "\n")
                else:
                    encrypted_data = encrypt(entry_address + ":" + entry_password, key, entry_salt) #inace samo vrati stari zapis u datoteku
                    new_lines.append(encrypted_data + "\n")

    if not found: #ako nisam azurirao podatak onda imam novi zapis
        salt = get_random_bytes(16)
        encrypted_data = encrypt(address + ":" + password, key, salt) #generiram novu sol za taj zapis i encryptam ga
        new_lines.append(encrypted_data + "\n")

    with open('passwords.txt', 'w') as file: #zapisi sve promjene u passwords.txt
        file.writelines(new_lines)

def get(master_password, address):
    with open('key_salt.txt', 'rb') as file:
        key_salt = file.read()
    key = scrypt(master_password.encode(), key_salt, 32, N=2**14, r=8, p=1) #key iz master passa i njegove soli

    with open('passwords.txt', 'r') as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()
        _, decrypted_data, success, dataTamper = decrypt(line, key) #decryptam liniju i dobijam njezine podatke i bool vrijednost uspjeha
        if dataTamper == True:
            print("Warning: The data has been tampered with!")
            sys.exit(1)
        if success == False:
            print("Incorrect master password!")
            sys.exit(1)
        if decrypted_data:
            entry_address, entry_password = decrypted_data.split(':', 1) #iz linije dohvati adresu i sifru i ako adresa odgovara trazenoj vrati njenu sifru
            if entry_address == address:
                return entry_password
    return None

def encrypt(data, key, salt):
    cipher = AES.new(key, AES.MODE_GCM, nonce=salt)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    hash_obj = SHA256.new()
    hash_obj.update(salt + tag + ciphertext)
    data_hash = hash_obj.digest()
    return base64.b64encode(salt + tag + ciphertext + data_hash).decode()

def decrypt(data, key):
    data = base64.b64decode(data.encode())
    salt = data[:16]
    tag = data[16:32]
    ciphertext = data[32:-32]
    stored_hash = data[-32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=salt)

    hash_obj = SHA256.new()
    hash_obj.update(salt + tag + ciphertext)
    current_hash = hash_obj.digest()

    if stored_hash != current_hash:
        return None, None, False, True

    try:
        return salt, cipher.decrypt_and_verify(ciphertext, tag).decode(), True, False
    except ValueError:
        return None, None, False, False
#-----------------------------------------------------------------------------------------------------------------------------------------------
command = input("Choose one of the following commands <init|put|get>: ")

if command not in ["init", "put", "get"]:
    print("Invalid command.")
    sys.exit(1)

if command == "init":
    master_password = get_master_password(print_warning=True)
    init(master_password)
    print("Password manager initialized.")
else:
    master_password = get_master_password(print_warning=False)
    if command == "put":
        address = input("Enter the name of the website: ")
        password = input("Enter your password: ")
        put(master_password, address, password)
        print("Stored password for " + address + ".")
    elif command == "get":
        address = input("Enter the name of the website: ")
        password = get(master_password, address)
        if password:
            print("Password for " + address + " is: " + password)
        else:
            print("No password found for " + address + ".")