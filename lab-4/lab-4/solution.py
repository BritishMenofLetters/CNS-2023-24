import requests
from pydantic import BaseModel
from base64 import b64decode
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Ciphertext(BaseModel):
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str


def xor_cipher(key: bytes, input: bytes) -> bytes:
    """Encrypts plaintext using XOR cipher with the provided key."""
    output = bytes(a ^ b for a, b in zip(key, input))
    return output


def derive_key(key_seed: str) -> bytes:
    """Derives encryption/decryption key from the given key_seed.
    Uses modern key derivation function (KDF) scrypt.
    """
    kdf = Scrypt(
        salt=b'',
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key


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


def get_challenge(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def get_token(url, username, password):
    response = requests.post(
        url=url,
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data={
            "username": username,
            "password": password
        }
    )
    response.raise_for_status()
    token = response.json().get("access_token")
    return token


def encrypt_chosen_plaintext(url, token, plaintext):
    response = requests.post(
        url=url,
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={"plaintext": plaintext}
    )
    response.raise_for_status()
    return response.json()


if __name__ == '__main__':
    host = "10.0.15.10"
    username = "stankovic_mateo"
    password = "thedatheul"
    
    # Get the challenge
    path = "ecb/challenge"
    url = f"http://{host}/{path}"
    response = get_challenge(url)
    challenge = Challenge(**response)

    # Get the token
    cookie = ""
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    path = "ecb/token"
    url = f"http://{host}/{path}"
    token = get_token(url, username, password)

    # Encrypt the chosen plaintext
    path = "ecb/"
    url = f"http://{host}/{path}"

    for i in range(1, 17):
        chosen_plaintext = "x" * (16 - i)
        response = encrypt_chosen_plaintext(
            url=url, token=token, plaintext=chosen_plaintext
        )
        ciphertext = Ciphertext(**response)
        ciphertext = b64decode(ciphertext.ciphertext)
        test_block = ciphertext[:16]

        for letter in alphabet:
            response = encrypt_chosen_plaintext(
                url=url, token=token, plaintext=chosen_plaintext + cookie + letter
            )
            ciphertext = Ciphertext(**response)
            ciphertext = b64decode(ciphertext.ciphertext)

            if ciphertext[:16] == test_block:
                cookie += letter
                break
    print(f"Cookie:{cookie} ")

    # derive the decryption key
    key = derive_key(cookie)

    # decrypt the challenge
    plaintext = decrypt_challenge(key, challenge)
    print(f"Decrypted challenge: {plaintext}")
    input()
