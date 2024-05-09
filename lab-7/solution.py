from base64 import b64decode, b64encode

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding as pkcs7_padding
from pydantic import BaseModel


class Ciphertext(BaseModel):
    iv: str
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str


def get_access_token(username, password, url):
    response = requests.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"username": username, "password": password},
    )
    response.raise_for_status()
    return response.json().get("access_token")


def encrypt_chosen_plaintext(plaintext: str, token: str, url: str) -> str:
    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"plaintext": plaintext},
    )

    response.raise_for_status()
    return response.json()


def get_challenge(url):
    response = requests.get(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response.raise_for_status()
    return response.json()


def decrypt_challenge(key: bytes, challenge: Challenge) -> str:
    """Decrypts encrypted challenge; reveals a password that can be
    used to unlock the next task/challenge.
    """
    iv = b64decode(challenge.iv)
    ciphertext = b64decode(challenge.ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext)
    plaintext += unpadder.finalize()
    return plaintext.decode()


def derive_key(key_seed: str, key_length=32) -> bytes:
    """Derives encryption/decryption key from the given key_seed.
    Uses modern key derivation function (KDF) scrypt.
    """
    kdf = Scrypt(
        salt=b"",
        length=key_length,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key

def exchange_RSA_keys_and_DH_params(url, token, public_RSA_key):
    if isinstance(public_RSA_key, bytes):
        public_RSA_key = public_RSA_key.decode()

    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"key": public_RSA_key},
    )
    response.raise_for_status()

    key = response.json().get('key')
    dh_params = response.json().get('dh_params')
    return key, dh_params

def exchange_DH_keys(url, token, key, signature):
    if isinstance(key, bytes):
        key = key.decode()    
        
    if isinstance(signature, bytes):
        signature = b64encode(signature).decode()    

    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={
            "key": key,
            "signature": signature
        },
    )

    response.raise_for_status()
    key = response.json().get("key")
    signature = response.json().get("signature")
    return key, signature


if __name__ == "__main__":
    host = "10.0.15.10"
    username = "stankovic_mateo"
    password = "pofriopris"

    # Get the token
    path = "asymmetric/token"
    url = f"http://{host}/{path}"

    # Step 1: Get the token
    token = get_access_token(username, password, url)
    print(f"\033[1mToken\033[0m: {token}")

    # ============================================================
    #   PROTOCOL IMPLEMENTATION
    # ============================================================

    # ------------------------------------------------------------
    #   Step 2: Generate client RSA key pair
    # ------------------------------------------------------------

    client_RSA_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    
    client_RSA_public = client_RSA_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    print(f'\033[1mClient RSA public\033[0m\n {client_RSA_public.decode()}')
    
    # ------------------------------------------------------------
    #   Step 3: Exchange public RSA keys and DH parameters
    # ------------------------------------------------------------
    path = "asymmetric/exchange/rsa-dh-params"
    url = f"http://{host}/{path}"

    server_RSA_public, DH_parameters = exchange_RSA_keys_and_DH_params(
            url=url,
            token=token,
            public_RSA_key=client_RSA_public
            )
    print(f'\033[1mServer RSA public\033[0m:\n {server_RSA_public}')
    print(f'\033[1mServer DH parameters\033[0m:\n {DH_parameters}')

    # De-serialization of RSA key and Dh params
    server_RSA_public = serialization.load_pem_public_key(server_RSA_public.encode())
    DH_parameters = serialization.load_pem_parameters(DH_parameters.encode())

    print(f'\033[1mPrime modulus p\033[0m:', DH_parameters.parameter_numbers().p)
    print(f'\033[1mPrime modulus p\033[0m:', DH_parameters.parameter_numbers().g)
    # ------------------------------------------------------------
    #   Step 4: Generate client DH key pair (based on DH params)
    # ------------------------------------------------------------

    client_DH_private = DH_parameters.generate_private_key()
    client_DH_public = client_DH_private.public_key()
    
    client_DH_public = client_DH_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"\033[1mClient DH public\033[0m:\n {client_DH_public.decode()}")    
    
    # ------------------------------------------------------------
    #   Step 5: Sign client DH public key with client RSA private
    # ------------------------------------------------------------

    signature = client_RSA_private.sign(
        client_DH_public,
        pkcs7_padding.PSS(
            mgf=pkcs7_padding.MGF1(hashes.SHA256()),
            salt_length=pkcs7_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # ------------------------------------------------------------
    #   Step 6: Authenticated DH key exchange/agreement
    # ------------------------------------------------------------

    path = "asymmetric/exchange/dh"
    url = f"http://{host}/{path}" 
    server_DH_public, signature = exchange_DH_keys(
        url=url, token=token, key=client_DH_public, signature=signature
    )
    
    print(f"\033[1mServer DH public:\033[0m\n {server_DH_public}")    
    print(f"\033[1mServer DH public signature:\033[0m\n{signature}")  

    # ------------------------------------------------------------
    #   Step 7: Verify authenticity of the server's DH
    #           public key and other info
    # ------------------------------------------------------------

    signature = b64decode(signature)
    server_DH_public = server_DH_public.encode()
    DH_parameters = DH_parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.ParameterFormat.PKCS3
    ) 
    
    message = DH_parameters + server_DH_public + client_DH_public
    
    server_RSA_public.verify(
        signature,
        message,
        pkcs7_padding.PSS(
            mgf=pkcs7_padding.MGF1(hashes.SHA256()),
            salt_length=pkcs7_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # ------------------------------------------------------------
    #   Step 8: Calculate DH shared secret 
    # ------------------------------------------------------------

    server_DH_public = serialization.load_pem_public_key(server_DH_public)
    shared_secret = client_DH_private.exchange(server_DH_public)
    
    print(f"\033[1mEstablished shared secret:\033[0m\n{shared_secret}")  
    # ------------------------------------------------------------
    #   Step 9: Derive 256 bit descryption key K
    # ------------------------------------------------------------

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ServerClient",
        info=None
    ).derive(shared_secret)
    
    print(f"\n\033[1mDecryption key:\033[0m\n f{key} \033[1m(length: {len(key)*8})\033[0m")

    # ------------------------------------------------------------
    #   Step 10: Get the challenge and decrypt it using K
    # ------------------------------------------------------------

    path = "asymmetric/challenge"
    url = f"http://{host}/{path}"
    response = get_challenge(url)
    challenge = Challenge(**response)
    decrypted_challenge = decrypt_challenge(key=key, challenge=challenge)
    
    print(f"\n\033[1mDecrypted challenge:\033[0m\n {decrypted_challenge}")
