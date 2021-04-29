
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import errno

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    

    def encrypt(self, message, key, encryption_type):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        if encryption_type == '128cfb':
            cipher = AES.new(key, AES.MODE_CFB, iv)
            return iv + cipher.encrypt(message)
        if encryption_type == '256cfb':
            cipher = AES.new(key, AES.MODE_CFB, iv)
        if encryption_type == '128ecb':
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.encrypt(message)
        if encryption_type == '256ecb':
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.encrypt(message)

        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name, encryption_type):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key, encryption_type)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key, encryption_type):
        iv = ciphertext[:AES.block_size]
        if encryption_type == '128cfb':
            cipher = AES.new(key, AES.MODE_CFB, iv)
        if encryption_type == '256cfb':
            cipher = AES.new(key, AES.MODE_CFB, iv)
        if encryption_type == '128ecb':
            cipher = AES.new(key, AES.MODE_ECB)
        if encryption_type == '256ecb':
            cipher = AES.new(key, AES.MODE_ECB)

        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name, encryption_type):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key, encryption_type)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)



def rsa_encryption():
    data = ''
    key = RSA.generate(2048)
    private_key = key.exportKey()
    with open("./private.pem", "wb") as f:
        f.write(private_key)

    public_key = key.publickey().exportKey()
    with open("receiver.pem", "wb") as f:
        f.write(public_key)



    file_name = input("Enter the file name. ")

    with open(file_name, "rb") as f:
        data = f.read()
    with open("encrypted_data.bin", "wb") as f:

        recipient_key = RSA.import_key(open("./receiver.pem").read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ] 

    with open("encrypted_data.bin", "rb") as f:

        private_key = RSA.import_key(open("private.pem").read())

        enc_session_key, nonce, tag, ciphertext = \
        [ f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        decoded_data = data.decode("utf-8")
        print(data.decode("utf-8"))
        with open("decrypted_rsa.txt", 'wb') as fo:
                fo.write(data)


def rsa_signature():
    number = int(input("Enter 1 to generate file and signature \nEnter 2 to verify\n"))
    if number == 1:
        file_name = input("Enter the file name. ")
        with open(file_name, "rb") as f:
            message = f.read()

        try:
            with open('privkey_for_rsa_signature.pem', 'r') as f:
                key = RSA.importKey(f.read())
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise
            # No private key, generate a new one. This can take a few seconds.
            key = RSA.generate(4096)
            with open('privkey_for_rsa_signature.pem', 'wb') as f:
                f.write(key.exportKey('PEM'))
            with open('pubkey_for_rsa_signature.pem', 'wb') as f:
                f.write(key.publickey().exportKey('PEM'))
        hasher = SHA256.new(message)
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(hasher)
        print(signature)
        with open("signature_for_%s.txt" % file_name, 'wb') as fo:
            fo.write(signature)

        
    elif number == 2:
        main_file = input("Enter the name of the file to be verified\n")
        signature_file = input("\nEnter the name of the signature file\n")
        signature_file = signature_file + ".txt"
        with open(main_file, "rb") as f:
            message = f.read()

        with open('pubkey_for_rsa_signature.pem', 'rb') as f:
            key = RSA.importKey(f.read())
        with open(signature_file, 'rb') as fo:
            signature = fo.read()
        hasher = SHA256.new(message)
        verifier = PKCS1_v1_5.new(key)
        if verifier.verify(hasher, signature):
            print('The signature is valid!')
        else:
            print('The signature is Invalid!')


key_16 = get_random_bytes(16)
key_32 = get_random_bytes(32)
enc_16 = Encryptor(key_16)
enc_32 = Encryptor(key_32)
clear = lambda: os.system('cls')

while True:
    choice = int(input(
                "1. Press '1' to use AES encryption.\n2. Press '2' to RSA encryption.\n3. Press '3' to use RSA signature.\n4. Press '4' to use SHA-256 hashing.\n5. Press '5' to exit.\n"))
    if choice == 1:
                encryption_type, action, file_name = input(
                "format example: 128cfb enc file.txt \n").split()
                if action == 'enc':
                    if encryption_type[0] == '1':
                        enc_16.encrypt_file(file_name, encryption_type)
                        print("\nFile encrypted!\n")
                    else:
                        enc_32.encrypt_file(file_name, encryption_type)
                        print("\nFile encrypted!\n")
                    
                elif action == 'dec':
                    if encryption_type[0] == '1':
                        enc_16.decrypt_file(file_name, encryption_type)
                        print("\nFile decrypted!\n")
                    else:
                        enc_32.decrypt_file(file_name, encryption_type)
                        print("\nFile decrypted!\n")
    elif choice ==2:
        rsa_encryption()

    elif choice == 3:
        rsa_signature()
    elif choice ==4:
        file_name = input("Enter the file name. ")
        with open(file_name, "rb") as f:
            message = f.read()
        hash = SHA256.new()
        hash.update(message)
        print(hash.hexdigest())


