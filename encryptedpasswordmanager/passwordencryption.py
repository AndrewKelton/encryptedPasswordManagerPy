import os
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives import padding

def newAccount():

    #collect username/password
    password = input("Enter a password to unlock encryption: ")
    username = input("Enter the username for your account: ")

    # plain text to be kept confidential
    plainpass = input("Enter the password: ")
    print(f"Plaintext: {plainpass}")
    plainpass = bytes(plainpass, 'utf-8')

    # 256-bit AES key
    key = os.urandom(256 // 8)

    # Create AES ECB Cipher
    aes_ecb_cipher = Cipher(AES(key), ECB())

    # pad the plaintext
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_plainpass = pkcs7_padder.update(plainpass) + pkcs7_padder.finalize()
    # print(f"Padded plaintext: {padded_plainpass}")

    # encyrpt padded plaintext
    encryptedpass = aes_ecb_cipher.encryptor().update(padded_plainpass)
    print(f"Encrypted password: {encryptedpass}")

    paddedDec = aes_ecb_cipher.decryptor().update(encryptedpass)
    pkcs7_unpadder = padding.PKCS7(AES.block_size).unpadder()
    decrypted = pkcs7_unpadder.update(paddedDec) + pkcs7_unpadder.finalize()

    file(username, encryptedpass)

    return password, decrypted


def file(a, b):
    
    # if os.stat('encryptedpasswords.txt').st_size == 0:

    f = open('encryptedpasswords.txt', 'a')

    f.write(f"Username: {a}\t")
    f.write(f"Password: {b}\n")
    f.close()

def menu():

    userinp = 1

    while userinp != 0:

        print("0-\t-Exit")
        print("1-\t-Enter New Account")
        print("2-\t-Decrypt Password")
        print("3-\t-Print All Accounts")

        userinp = int(input("Enter choice: "))

        if userinp == 1:

            password, decrypted = newAccount()
            decrypted = str(decrypted, encoding='utf-8')

        elif userinp == 2:

            encryptinp = input("Enter the password used to encrypt: ")

            if encryptinp == password:

                print("Decrypting password...")
                print(f"Decrypted password: {decrypted}")
                
            else:

                print("Incorrect password")
                
        elif userinp == 3:

            f = open('encryptedpasswords.txt', 'r')
            print(f.read())
            f.close

    print("All usernames and passwords have been uploaded to 'encryptedpasswords.txt'")

menu()

# with open('encryptedpasswords.txt', 'r') as f:

#         for line in f:
#             print("------------------------------")
#             for word in line.split():
#                 print(f"{word}\t")
#     f.close()