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
            memory_cost=2*1048576,
            parallelism=2,
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
        pass_length = ((len(secret_1)*len(secret_2))%16)+128
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


def encryptor(input_file, secret_1, secret_2):
    key = hash_bytes(secret_1, secret_2)
    key = key[-32:]


def decryptor(input_file, secret_1, secret_2):
    key = hash_bytes(secret_1, secret_2)
    key = key[-32:]


print("\n\nenigma_hasher by shiva_the_cryptic")
while True:
    print("\n\n")

    secret_1 = input("secret 1 : ")
    secret_2 = input("secret 2 : ")
    secret_1 = secret_1.replace(" ","")
    secret_2 = secret_2.replace(" ","")


    print("\n")
    hasher(secret_1, secret_2)

    reset = input("exit (y/n) ? ")
    if reset == "y":
        break;
