import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

Program_Header = '''
-----------------------------------------------------------------------------------------------------
__     __         _                 ____  ____    _    
\ \   / /__  _ __| |_ _____  __    |  _ \/ ___|  / \   
 \ \ / / _ \| '__| __/ _ \ \/ /____| |_) \___ \ / _ \  
  \ V / (_) | |  | ||  __/>  <_____|  _ < ___) / ___ \ 
   \_/ \___/|_|   \__\___/_/\_\    |_| \_\____/_/   \_\ 

Module: Vortex-RSA
Version: 0.5.0
Author: WorldDstroyer
Date: 9-22-2020
Description: Utilize the RSA algorithm to work with asymmetric encryption.

Manual Guide:
1. First, you want to generate a unique RSA key pair. The pair will be written to (Private.pem),
and (Public.pem).

2. If you want to send someone a secret that only they can decrypt, you must encrypt your data
using -their- public key. Have them send you their (Public.pem) file, and move it into the folder
named "Public-Import."

3. Then, if they want to use -their- private key to decrypt the data you signed with their public
key, send them -your- (Encrypted_Data.bin) file, and have them move it into their "Data-Import"
folder.
-----------------------------------------------------------------------------------------------------'''
print(Program_Header)

def Key_Generation():
    Key_Prompt = input("Generate an RSA key pair? (y/n) ")
    if Key_Prompt == "y":
        Key_Length_List = [
            "1024",
            "2048",
            "4096",
        ]
        Key_Length = input("RSA Key Length: ")
        if Key_Length in Key_Length_List:
            # The RSA key pair is written to (Private.pem) and (Public.pem), respectively.
            print("Generating key pair with length (%d)..." % int(Key_Length))
            Key = RSA.generate(int(Key_Length))
            Private_Key = Key.export_key()
            
            File_Private = open("Private.pem", "wb")
            File_Private.write(Private_Key)
            File_Private.close()
            
            Public_Key = Key.publickey().export_key()

            File_Public = open("Public.pem", "wb")
            File_Public.write(Public_Key)
            File_Public.close()
            print("-----------------------------------------------------------------------------------------------------")
            print(Private_Key)
            print("")
            print(Public_Key)
            print("-----------------------------------------------------------------------------------------------------")
            print("Private and public keys written to (Private.pem) and (Public.pem)!")
            Main()

        elif Key_Length not in Key_Length_List:
            print("Error: Invalid key pair length. Must be either 1024, 2048, or 4096.")
            Key_Generation()

    elif Key_Prompt == "n":
        Main()

    else:
        print("Error: Response invalid.")
        time.sleep(1.0)
        Key_Generation()

def Main():
    RSA_Mode = input("1: Encrypt | 2: Decrypt | 3: Exit ")
    if RSA_Mode == "1":
        Input_Data = input("(Encrypt) Plaintext Data: ")
        Input_Data = Input_Data.encode("utf-8")
        File = open("Encrypted_Data.bin", "wb")

        input("The ciphertext will be written to (Encrypted_Data.bin)! Proceed? ")
        input("The public key will be imported from (/Public-Import/Public.pem)! Proceed? ")

        Program_Directory = os.path.dirname(__file__)
        Relative_Path = "Public-Import/Public.pem"
        File_Path = os.path.join(Program_Directory, Relative_Path)
        Public_Key = RSA.import_key(open(File_Path).read())

        Session_Key = get_random_bytes(16)

        Cipher_RSA = PKCS1_OAEP.new(Public_Key)
        Session_Key_Encrypted = Cipher_RSA.encrypt(Session_Key)

        Cipher_AES = AES.new(Session_Key, AES.MODE_EAX)
        Ciphertext, Tag = Cipher_AES.encrypt_and_digest(Input_Data)
        [ File.write(x) for x in (Session_Key_Encrypted, Cipher_AES.nonce, Tag, Ciphertext) ]
        File.close()
        print("The ciphertext was encrypted with the imported public key (/Public-Import/Public.pem) and exported to (Encrypted_Data.bin)! ")
        Main()

    elif RSA_Mode == "2":
        input("The ciphertext will be imported from (/Data-Import/Encrypted_Data.bin) and decrypted using your private key (Private.pem)! Proceed? ")

        Program_Directory = os.path.dirname(__file__)
        Relative_Path = "Data-Import/Encrypted_Data.bin"
        File_Path = os.path.join(Program_Directory, Relative_Path)
        File = open(File_Path, "rb")

        Private_Key = RSA.import_key(open("Private.pem").read())

        Session_Key_Encrypted, Nonce, Tag, Ciphertext = \
        [ File.read(x) for x in (Private_Key.size_in_bytes(), 16, 16, -1) ]

        # Decrypt the session key with the private RSA key.
        Cipher_RSA = PKCS1_OAEP.new(Private_Key)
        session_key = Cipher_RSA.decrypt(Session_Key_Encrypted)

        # Decrypt the data with the AES session key.
        Cipher_AES = AES.new(session_key, AES.MODE_EAX, Nonce)
        Output_Data = Cipher_AES.decrypt_and_verify(Ciphertext, Tag)
        print("Output Data:", Output_Data.decode("utf-8"))
        input("Press 'Enter' to continue... ")
        Main()

    elif RSA_Mode == "3":
        print("Exiting program...")
        time.sleep(1.0)

    else:
        print("Error: Response invalid. ")
        time.sleep(1.0)
        Main()

Key_Generation()