import argon2

#pip install cryptography
#pip install argon2-cffi

def hash_bytes(secret_1, secret_2):
    try:
        secret_2_bytes = secret_2.encode()
        while len(secret_2_bytes) < 32:
            secret_2_bytes += b'\x00'
        else:
            secret_2_bytes = secret_2_bytes[:32]
        key_dev = argon2.PasswordHasher(
            time_cost=20,
            memory_cost=3*1048576,
            parallelism=2,
            hash_len=512,
            salt_len=32,
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
        pass_length = 511
        print("\n")
        print(key_str[0:pass_length])
        print("\n")
    except Exception as e:
        print(f"Exception ! - hasher - {e}")
        exit()


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
