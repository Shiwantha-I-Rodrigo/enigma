from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
import os, re, secrets, argon2


#pip install cryptography
#pip install argon2-cffi
#pip install tqdm


def hash_bytes(secret_1, secret_2):
    try:
        secret_2_bytes = secret_2.encode()

        while len(secret_2_bytes) < 16:
            secret_2_bytes += b'\x00'
        else:
            secret_2_bytes = secret_2_bytes[:16]

        key_dev = argon2.PasswordHasher(
            time_cost=1,
            memory_cost=8*1048576,
            parallelism=4,
            hash_len=512,
            salt_len=16,
            type=argon2.low_level.Type.ID
        )
        print("deriving key...")
        argon_str = key_dev.hash(password=secret_1, salt=secret_2_bytes)
        print("key derived !")
        argon_hash = argon_str.split('$')[-1]
        return argon_hash.encode()
    except Exception as e:
        print(f"Exception ! - hash_bytes - {e}")
        exit()


def hasher(secret_1, secret_2):
    try:
        key_str = hash_bytes(secret_1,secret_2).decode()
        key_str = key_str.replace("/","@")
        key_str = key_str.replace("+","*")
        pass_length = ((len(secret_1)*len(secret_2))%16)+16
        do_flag = True
        while do_flag == True:
            for i in range(0,len(key_str)-pass_length):
                    match_l = re.search(r'[a-z]',key_str[i:i+pass_length])
                    match_u = re.search(r'[a-z]',key_str[i:i+pass_length])
                    match_n = re.search(r'[0-9]',key_str[i:i+pass_length])
                    match_s = re.compile(r'[^a-zA-Z0-9]').search(key_str[i:i+pass_length])
                    if match_l and match_u and match_n and match_s:
                        print("\n")
                        print(key_str[i:i+pass_length])
                        print("\n")
                        do_flag = False
                        break
            if do_flag:
                key_str = hash_bytes(key_str, key_str).decode()
    except Exception as e:
        print(f"Exception ! - hasher - {e}")
        exit()


def encrypt_large_file(input_file, key):
    try:
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        chunk_size=1024*1024
        total_size = os.path.getsize(input_file)
        with open(input_file,'rb') as infile, open(input_file + ".enc",'wb') as outfile, open(input_file + ".enc.iv",'wb') as ivfile:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Encrypting", position=0) as pbar:
                while chunk := infile.read(chunk_size):
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                    pbar.update(len(chunk))
            final_chunk = encryptor.finalize()
            outfile.write(final_chunk)
            ivfile.write(iv)
    except Exception as e:
        print(f"Exception ! - encrypt_large_file - {e}")
        if os.path.exists(input_file + ".enc"): os.remove(input_file + ".enc")
        if os.path.exists(input_file + ".enc.iv"): os.remove(input_file + ".enc.iv") 
        exit()


def encrypt_file_name(input_file, key):
    try:
        iv = secrets.token_bytes(16)
        file_name = str(os.path.basename(input_file)).encode()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_name) + encryptor.finalize()
        new_file_name = encrypted_data.hex()
        new_file = os.path.join(os.path.dirname(input_file), new_file_name)
        os.rename(input_file, new_file)
        with open(new_file + ".iv",'wb') as ivfile:
            ivfile.write(iv)
        return new_file
    except Exception as e:
        print(f"Exception ! - encrypt_file_name - {e}")
        if not os.path.exists(input_file):
            os.rename(new_file, input_file)
            if os.path.exists(new_file + ".iv"):
                os.remove(new_file + ".iv") 
        exit()


def decrypt_large_file(input_file, key):
    try:
        with open(input_file + ".iv", 'rb') as ivfile:
            iv = ivfile.read()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        chunk_size=1024*1024
        total_size = os.path.getsize(input_file)
        output_file = input_file[:-4]
        with open(input_file,'rb') as infile, open(output_file,'wb') as outfile:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Decrypting", position=0) as pbar:
                while chunk := infile.read(chunk_size):
                    decrypted_chunk = decryptor.update(chunk)
                    outfile.write(decrypted_chunk)
                    pbar.update(len(chunk))
            final_chunk = decryptor.finalize()
            outfile.write(final_chunk)
    except Exception as e:
        print(f"Exception ! - decrypt_large_file - {e}")
        if os.path.exists(input_file[:-4]): os.remove(input_file[:-4])
        exit()


def decrypt_file_name(input_file, key):
    try:
        with open(input_file + ".iv", 'rb') as ivfile:
            iv = ivfile.read()
        file_name = bytes.fromhex(os.path.basename(input_file))
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(file_name) + decryptor.finalize()
        new_file_name = decrypted_data.decode()
        new_file = os.path.join(os.path.dirname(input_file), new_file_name)
        os.rename(input_file, new_file)
        return new_file
    except Exception as e:
        print(f"Exception ! - decrypt_file_name - {e}")
        exit()


def encryptor(input_file, secret_1, secret_2):
    key = hash_bytes(secret_1, secret_2)
    key = key[-32:]
    encrypt_large_file(input_file,key)
    file = encrypt_file_name(input_file + ".enc", key)
    print(f"{input_file} encrypted!")


def decryptor(input_file, secret_1, secret_2):
    key = hash_bytes(secret_1, secret_2)
    key = key[-32:]
    file = decrypt_file_name(input_file, key)
    decrypt_large_file(file,key)
    os.rename(file,input_file)
    print(f"{input_file} decrypted!")


def batch_encryptor(input_folder, secret_1, secret_2, level, extention):
    key = hash_bytes(secret_1, secret_2)
    key = key[-32:]
    for root, dirs, files in os.walk(input_folder):
        current_depth = root[len(input_folder):].count(os.path.sep)
        if current_depth <= level:
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    if not os.path.isdir(file_path) and file.endswith(extention):
                        encrypt_large_file(file_path,key)
                        print(f"{file_path} encrypted!")
                        new_file = encrypt_file_name(file_path + ".enc", key)
                        print(f"{file_path} >> {new_file} renamed!")
                except:
                    print(f"! exception {file}")


def batch_decryptor(input_folder, secret_1, secret_2, level):
    key = hash_bytes(secret_1, secret_2)
    key = key[-32:]
    for root, dirs, files in os.walk(input_folder):
        current_depth = root[len(input_folder):].count(os.path.sep)
        if current_depth <= level:
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    if not os.path.isdir(file_path) and '.' not in file:
                        new_file = decrypt_file_name(file_path, key)
                        print(f"{file_path} >> {new_file} renamed!")
                        decrypt_large_file(new_file,key)
                        print(f"{file_path} decrypted!")
                        os.rename(new_file,file_path)
                        print(f"{new_file} >> {file_path} renamed!")
                except:
                    print(f"! exception {file}")


print("\n\nenigma2 by shiva_the_cryptic")
while True:
    print("\n\n")
    print("1. Password Generator")
    print("2. File Encryptor")
    print("3. File Decryptor")
    print("4. Batch Encryptor")
    print("5. Batch Decryptor")
    print("9. Exit")
    print("\n\n")
    choice = input("Enter Your Choice : ")

    if choice == "9":
        break

    if choice == "4" or choice == "5" :
        input_folder = input("root path : ")
        if choice == "4":
            print("avoid batch encrypting files in folders with already encrypted files specially of same extention !")
            extention = input("insert extention (include dot) : ")
        level = int(-1)
        while not level >= 0:
            try:
                level = int(input("depth level ( > 0): "))
            except:
                print("! enter a valid number")
    elif choice == "2" or choice == "3":
        input_file = input("input file : ")
        input_file = input_file.replace(" ","")

    secret_1 = input("secret 1 : ")
    secret_2 = input("secret 2 : ")
    secret_1 = secret_1.replace(" ","")
    secret_2 = secret_2.replace(" ","")

    print("\n")
    if choice == "1":
        hasher(secret_1, secret_2)
    elif choice == "2":
        encryptor(input_file, secret_1, secret_2)
    elif choice == "3":
        decryptor(input_file, secret_1, secret_2)
    elif choice == "4":
        batch_encryptor(input_folder, secret_1, secret_2, level, extention)
    elif choice == "5":
        batch_decryptor(input_folder, secret_1, secret_2, level)
    else:
        print("! please enter a valid choice")
