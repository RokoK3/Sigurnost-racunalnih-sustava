import sys
import getpass
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def get_all_users():
    users = []
    with open("users.txt", "r") as file:
        for line in file:
            row = line.strip().split(' ')
            users.append(row)
    return users

def rewrite_users(users):
    with open("users.txt", "w") as file:
        for row in users:
            file.write(' '.join(row) + '\n')

def hash_password(password, salt):
    sha256 = SHA256.new()
    sha256.update((password + salt.hex()).encode())
    return sha256.hexdigest()

def find_user(username, users):
    for row in users:
        if row[1] == username:
            return row
    return None

#========================================================================================================================

command = sys.argv[1]
username = sys.argv[2]

if command == "add":
    users = get_all_users()
    if find_user(username, users) is not None:
        print("User already exists.")
        sys.exit(1)

    password = getpass.getpass("Password: ")
    repeat_password = getpass.getpass("Repeat Password: ")

    if password != repeat_password:
        print("User add failed. Password mismatch.")
        sys.exit(1)

    salt = get_random_bytes(16)
    password_hash = hash_password(password, salt)
    flag = '0'

    users.append([flag, username, salt.hex(), password_hash])
    rewrite_users(users)
    print("User " + username + " successfully added.")

elif command == "passwd":
    users = get_all_users()
    user = find_user(username, users)
    if not user:
        print("User not found.")
        sys.exit(1)

    password = getpass.getpass("Password: ")
    repeat_password = getpass.getpass("Repeat Password: ")

    if password != repeat_password:
        print("Password change failed. Password mismatch.")
        sys.exit(1)

    new_salt = get_random_bytes(16) 
    password_hash = hash_password(password, new_salt)
    flag = '0'  
    user[0] = flag
    user[2] = new_salt.hex() 
    user[3] = password_hash
    rewrite_users(users)
    print("Password change successful.")

elif command == "forcepass":
    users = get_all_users()
    user = find_user(username, users)
    if user is None:
        print("User not found.")
        sys.exit(1)
    user[0] = '1'
    rewrite_users(users)
    print("User will be requested to change password on next login.")

elif command == "del":
    users = get_all_users()
    user = find_user(username, users)
    if user is None:
        print("User not found.")
        sys.exit(1)
    users.remove(user)
    rewrite_users(users)
    print("User successfully removed.")