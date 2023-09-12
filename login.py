import sys
import getpass
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def hash_password(password, salt):
    sha256 = SHA256.new()
    sha256.update((password + salt.hex()).encode())
    return sha256.hexdigest()

username = sys.argv[1]

users = []
with open("users.txt", "r") as file:
    for line in file:
        row = line.strip().split(' ')
        users.append(row)

user = None
for row in users:
    if row[1] == username:
        user = row
        break

while True:
    password = getpass.getpass("Password: ")
    if user:
        salt = bytes.fromhex(user[2])
        password_hash = hash_password(password, salt)

        if password_hash == user[3]:
            if user[0] == '1':
                while True:
                    new_password = getpass.getpass("New password: ")
                    repeat_password = getpass.getpass("Repeat new password: ")

                    if new_password != repeat_password:
                        print("Password change failed. Password mismatch.")
                        continue

                    new_password_hash = hash_password(new_password, salt)
                    if new_password_hash == user[3]:
                        print("New password must be different from the previous password.")
                    else:
                        break

                user[0] = '0'
                new_salt = get_random_bytes(16)
                user[2] = new_salt.hex()
                user[3] = hash_password(new_password, new_salt)
                with open("users.txt", "w") as file:
                    for rows in users:
                        file.write(' '.join(rows) + '\n')
            print("Login successful.")
            break
        else:
            print("Username or password incorrect.")
    else:
        print("Username or password incorrect.")
        break