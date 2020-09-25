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
Version: 1.0.0
Author: WorldDstroyer
Date: 9-25-2020
Description: Utilize the RSA algorithm to work with asymmetric encryption.

Manual Guide:
1. First, you want to generate a unique RSA key pair. It is recommended that the chosen key has a
length of either 2048, or 4096, as RSA-1024 is no longer considered feasibly secure. You can then
choose for the key pair to be written to:
/Data-Stored/Key_Private.pem
/Data-Stored/Key_Public.pem
Alternatively, they can be pasted manually (broken as of Vortex-RSA-1.0.0).

2. If you want to send someone a secret that only they can decrypt, you must encrypt your data
using -their- public key. Have them send you their (Key_Public.pem) file, and move it into the
folder named "Data-Import." Asymmetric encryption means that data encrypted with one key can
only be decrypted using the other. This is a smart way to disseminate secrets openly.

3. Then, if they want to use -their- private key to decrypt the data that was signed with their
public key, send them the ciphertext written to -your- (Data_Encrypted.bin) file, and have them
move it into their "Data-Import" folder.
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
            # The key pair is generated and printed.
            print("Generating key pair with length (%d)..." % int(Key_Length))
            Key = RSA.generate(int(Key_Length))
            Key_Private = Key.export_key()
            Key_Public = Key.publickey().export_key()

            print("-----------------------------------------------------------------------------------------------------")
            print(Key_Private)
            print("")
            print(Key_Public)
            print("-----------------------------------------------------------------------------------------------------")

            # The key save option is prompted.
            Save_Prompt = input("Save the key pair to (/Data-Stored/Key_*.pem)? (y/n) ")
            if Save_Prompt == "y": # Save = "Yes"
                # If the response is "yes," the RSA key pair is written to (/Data-Stored/Key_Private.pem) and (/Data-Stored/Key_Public.pem), respectively.
                Program_Directory = os.path.dirname(__file__)
                Relative_Path = "Data-Stored/Key_Private.pem"
                File_Path = os.path.join(Program_Directory, Relative_Path)
                File_Private = open(File_Path, "wb")
                File_Private.write(Key_Private)
                File_Private.close()

                Relative_Path = "Data-Stored/Key_Public.pem"
                File_Path = os.path.join(Program_Directory, Relative_Path)
                File_Public = open(File_Path, "wb")
                File_Public.write(Key_Public)
                File_Public.close()
                print("Private and public keys written to (/Data-Stored/Key_Private.pem) and (/Data-Stored/Key_Public.pem)!")
                time.sleep(1.0)
                Main()

            elif Save_Prompt == "n": # Save = "No"
                Main()

            else:
                print("Error: Response invalid.")
                time.sleep(1.0)
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
    RSA_Mode = input("0: Generate RSA Key Pair | 1: Encrypt | 2: Decrypt | 3: Wipe Data | 4: Exit ")
    if RSA_Mode == "0": # - Generate -
        Key_Generation()

    elif RSA_Mode == "1": # - Encrypt -
        Input_Data = input("(Encrypt) Plaintext Data: ")
        Input_Data = Input_Data.encode("utf-8")

        Key_Import_Prompt = input("Import the recipient's public key from (/Data-Import/Key_Public.pem)? (y/n) ")
        if Key_Import_Prompt == "y": # Import = "Yes"
            try:
                input("The recipient's public key will be imported from (/Data-Import/Key_Public.pem)! Proceed? ")
                # - Public Key Import -
                Program_Directory = os.path.dirname(__file__)
                Relative_Path = "Data-Import/Key_Public.pem"
                File_Path = os.path.join(Program_Directory, Relative_Path)
                Key_Public = RSA.import_key(open(File_Path).read())
                #

                input("The ciphertext will be written to (/Data-Stored/Data_Encrypted.bin)! Proceed? ")
                # - Ciphertext Export -
                Relative_Path = "Data-Stored/Data_Encrypted.bin"
                File_Path = os.path.join(Program_Directory, Relative_Path)
                File_Ciphertext = open(File_Path, "wb")
                #

                # - Encryption Process -
                Session_Key = get_random_bytes(16)
                Cipher_RSA = PKCS1_OAEP.new(Key_Public)
                # AES session key encrypted with the given public key.
                Session_Key_Encrypted = Cipher_RSA.encrypt(Session_Key)

                # Original session key encrypted with the AES cipher.
                Cipher_AES = AES.new(Session_Key, AES.MODE_EAX)
                Ciphertext, Tag = Cipher_AES.encrypt_and_digest(Input_Data)
                [ File_Ciphertext.write(x) for x in (Session_Key_Encrypted, Cipher_AES.nonce, Tag, Ciphertext) ]
                File_Ciphertext.close()

                print("The ciphertext was encrypted with the imported public key (/Public-Import/Public.pem) and exported to (/Data-Stored/Data_Encrypted.bin)! ")
                Main()
            except FileNotFoundError:
                print("Error: No key found at (/Data-Import/Key_Public.pem). ")
                time.sleep(1.0)
                Main()

        elif Key_Import_Prompt == "n": # Import = "No"
            try:
                Key_Input = input("Public Key (Recipient): ")
                Key_Public = RSA.import_key(Key_Input)

                input("The ciphertext will be written to (/Data-Stored/Data_Encrypted.bin)! Proceed? ")
                Program_Directory = os.path.dirname(__file__)
                Relative_Path = "Data-Stored/Data_Encrypted.bin"
                File_Path = os.path.join(Program_Directory, Relative_Path)
                File = open(File_Path, "wb")

                Session_Key = get_random_bytes(16)

                Cipher_RSA = PKCS1_OAEP.new(Key_Public)
                Session_Key_Encrypted = Cipher_RSA.encrypt(Session_Key)

                Cipher_AES = AES.new(Session_Key, AES.MODE_EAX)
                Ciphertext, Tag = Cipher_AES.encrypt_and_digest(Input_Data)
                [ File.write(x) for x in (Session_Key_Encrypted, Cipher_AES.nonce, Tag, Ciphertext) ]
                File.close()
                print("The ciphertext was encrypted with the inserted public key, and exported to (/Data-Stored/Data_Encrypted.bin)! ")
                Main()
            except ValueError:
                print("Error: Malformed key object. ")
                time.sleep(1.0)
                Main()

        else:
            print("Error: Response invalid.")
            time.sleep(1.0)
            Main()

    elif RSA_Mode == "2": # - Decrypt -
        Key_Import_Prompt = input("Import the private key from (/Data-Stored/Key_Private.pem)? (y/n) ")
        if Key_Import_Prompt == "y": # Import = "Yes"
            try:
                input("The ciphertext will be imported from (/Data-Import/Data_Encrypted.bin) and decrypted using your private key (/Data-Stored/Key_Private.pem)! Proceed? ")

                Program_Directory = os.path.dirname(__file__)
                Relative_Path = "Data-Import/Data_Encrypted.bin"
                File_Path = os.path.join(Program_Directory, Relative_Path)
                File = open(File_Path, "rb")

                Relative_Path = "Data-Stored/Key_Private.pem"
                File_Path = os.path.join(Program_Directory, Relative_Path)
                Key_Private = RSA.import_key(open(File_Path).read())

                Session_Key_Encrypted, Nonce, Tag, Ciphertext = \
                [ File.read(x) for x in (Key_Private.size_in_bytes(), 16, 16, -1) ]

                # Decrypt the session key with the private RSA key.
                Cipher_RSA = PKCS1_OAEP.new(Key_Private)
                Session_Key = Cipher_RSA.decrypt(Session_Key_Encrypted)

                # Decrypt the data with the AES session key.
                Cipher_AES = AES.new(Session_Key, AES.MODE_EAX, Nonce)
                Output_Data = Cipher_AES.decrypt_and_verify(Ciphertext, Tag)
                print("(Decrypt) Output Data:", Output_Data.decode("utf-8"))
                input("Press 'Enter' to continue... ")
                Main()
            except FileNotFoundError:
                print("Error: No ciphertext found at (/Data-Import/Data_Encrypted.bin), or no private key found at (/Data-Stored/Key_Private.pem). ")
                time.sleep(1.0)
                Main()
        
        elif Key_Import_Prompt == "n": # Import = "No"
            Key_Input = input("Private Key: ")
            Key_Private = RSA.import_key(Key_Input)

            Program_Directory = os.path.dirname(__file__)
            Relative_Path = "Data-Import/Data_Encrypted.bin"
            File_Path = os.path.join(Program_Directory, Relative_Path)
            File = open(File_Path, "rb")

            Session_Key_Encrypted, Nonce, Tag, Ciphertext = \
            [ File.read(x) for x in (Key_Private.size_in_bytes(), 16, 16, -1) ]

            # Decrypt the session key with the private RSA key.
            Cipher_RSA = PKCS1_OAEP.new(Key_Private)
            Session_Key = Cipher_RSA.decrypt(Session_Key_Encrypted)

            # Decrypt the data with the AES session key.
            Cipher_AES = AES.new(Session_Key, AES.MODE_EAX, Nonce)
            Output_Data = Cipher_AES.decrypt_and_verify(Ciphertext, Tag)
            print("Output Data:", Output_Data.decode("utf-8"))
            input("Press 'Enter' to continue... ")
            Main()

        else:
            print("Error: Response invalid.")
            time.sleep(1.0)
            Main()

    elif RSA_Mode == "3": # - Wipe Data -
        Erase_Prompt = input("Erase the data in (/Data-Stored/)? (y/n) ")
        if Erase_Prompt == "y": # Wipe Data = "Yes"

            Program_Directory = os.path.dirname(__file__)

            Data_Path = "Data-Stored/Key_Private.pem"
            Key_Private_File = os.path.join(Program_Directory, Data_Path)
            File = open(Key_Private_File, "wb")
            Erasure = b""
            File.write(Erasure)
            File.close()
            print("Wiped data from (/Data-Stored/Key_Private.pem)!")

            Data_Path = "Data-Stored/Key_Public.pem"
            Key_Public_File = os.path.join(Program_Directory, Data_Path)
            File = open(Key_Public_File, "wb")
            Erasure = b""
            File.write(Erasure)
            File.close()
            print("Wiped data from (/Data-Stored/Key_Public.pem)!")

            Data_Path = "Data-Stored/Data_Encrypted.bin"
            Data_Encrypted_File = os.path.join(Program_Directory, Data_Path)
            File = open(Data_Encrypted_File, "wb")
            Erasure = b""
            File.write(Erasure)
            File.close()
            print("Wiped data from (/Data-Stored/Data_Encrypted.bin)!")

            Main()

        elif Erase_Prompt == "n": # Wipe Data = "No"
            Main()

        else:
            print("Error: Response invalid.")
            time.sleep(1.0)
            Main()

    elif RSA_Mode == "4": # - Exit -
        print("Exiting program...")
        time.sleep(1.0)

    else:
        print("Error: Response invalid. ")
        time.sleep(1.0)
        Main()

Key_Generation()