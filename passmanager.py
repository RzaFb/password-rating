import argparse
import hashlib
import os
import json
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


def create_password_entry(args):
    passwords_data = load_encrypted_data(args.encryption_key)
    passwords_data[args.name] = {
        'password': generate_secure_password(args.encryption_key, args.password_length),
        'comment': args.comment
    }
    save_encrypted_data(passwords_data, args.encryption_key)
    print(f"Password entry for {args.name} created.")


def display_all_password_entries(args):
    passwords_data = load_encrypted_data(args.encryption_key)
    for name, details in passwords_data.items():
        print(f"Name: {name}" + f"    Password: {details['password']}" + f"    Comment: {details['comment']}\n")


def select_password_entry(args):
    passwords_data = load_encrypted_data(args.encryption_key)
    if args.name in passwords_data:
        print(f"Password: {passwords_data[args.name]['password']}" + f"    Comment: {passwords_data[args.name]['comment']}")


def update_password_entry(args):
    passwords_data = load_encrypted_data(args.encryption_key)
    if args.name in passwords_data:
        passwords_data[args.name]['password'] = generate_secure_password(args.encryption_key, args.password_length)
        save_encrypted_data(passwords_data, args.encryption_key)
        print(f"Password entry for {args.name} updated.")


def delete_password_entry(args):
    passwords_data = load_encrypted_data(args.encryption_key)
    if args.name in passwords_data:
        del passwords_data[args.name]
        save_encrypted_data(passwords_data, args.encryption_key)
        print(f"Password entry for {args.name} deleted.")


def generate_secure_password(user_input, password_length):
    salt = os.urandom(16)
    combined_input = salt + user_input.encode()
    hashed = hashlib.sha512(combined_input).digest()
    return b64encode(hashed)[:password_length].decode('utf-8')


def encrypt_text(data, encryption_key):
    cipher = AES.new(pad(encryption_key.encode(), AES.block_size), AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return b64encode(cipher.iv + ciphertext_bytes).decode('utf-8')


def decrypt_text(encrypted_data, decryption_key):
    data = b64decode(encrypted_data)
    initialization_vector = data[:AES.block_size]
    ciphertext_bytes = data[AES.block_size:]
    cipher = AES.new(pad(decryption_key.encode(), AES.block_size), AES.MODE_CBC, initialization_vector)
    return unpad(cipher.decrypt(ciphertext_bytes), AES.block_size).decode('utf-8')


def generate_multiple_secure_passwords(args):
    passwords = []
    for _ in range(int(args.number)):
        passwords.append(generate_secure_password("0000", random.randint(4, 20)))
    with open('test.txt', 'w') as file:
        file.write('\n'.join(passwords))


def load_encrypted_data(decryption_key):
    if not os.path.exists('passwords.enc'):
        return {}
    with open('passwords.enc', 'r') as file:
        encrypted_data = file.read()
    data = decrypt_text(encrypted_data, decryption_key)
    return json.loads(data)


def save_encrypted_data(data, encryption_key):
    data_to_save = json.dumps(data)
    encrypted_data = encrypt_text(data_to_save, encryption_key)
    with open('passwords.enc', 'w') as file:
        file.write(encrypted_data)


def is_valid_encryption_key(encryption_key):
    if os.path.exists('passwords.enc'):
        try:
            load_encrypted_data(encryption_key)
            return True
        except ValueError:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Password Management Tool")
    subparsers = parser.add_subparsers(help='commands')

    create_parser = subparsers.add_parser('create', help='Create a new password entry')
    create_parser.add_argument('name', help='Name of the password entry')
    create_parser.add_argument('-comment', help='Comment for the password entry', required=True)
    create_parser.add_argument('-encryption_key', help='Encryption key (user simple password)', required=True)
    create_parser.add_argument('-password_length', type=int, help='Length of the generated password', required=True)
    create_parser.set_defaults(func=create_password_entry)

    display_parser = subparsers.add_parser('display', help='Display all password entries')
    display_parser.add_argument('-encryption_key', help='Encryption key (user simple password)', required=True)
    display_parser.set_defaults(func=display_all_password_entries)

    select_parser = subparsers.add_parser('select', help='Select a password entry')
    select_parser.add_argument('name', help='Name of the password entry')
    select_parser.add_argument('-encryption_key', help='Encryption key (user simple password)', required=True)
    select_parser.set_defaults(func=select_password_entry)

    update_parser = subparsers.add_parser('update', help='Update an existing password entry')
    update_parser.add_argument('name', help='Name of the password entry')
    update_parser.add_argument('-encryption_key', help='Encryption key (user simple password)', required=True)
    update_parser.add_argument('-password_length', type=int, help='New length of the generated password', required=True)
    update_parser.set_defaults(func=update_password_entry)

    delete_parser = subparsers.add_parser('delete', help='Delete a password entry')
    delete_parser.add_argument('name', help='Name of the password entry')
    delete_parser.add_argument('-encryption_key', help='Encryption key (user simple password)', required=True)
    delete_parser.set_defaults(func=delete_password_entry)

    generate_parser = subparsers.add_parser('generate', help='Generate passwords')
    generate_parser.add_argument('-number', help='Number of passwords generation', required=True)
    generate_parser.set_defaults(func=generate_multiple_secure_passwords)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
