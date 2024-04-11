from base64 import b64decode

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
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


def get_wordlist(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.content


def get_encrypted_cookie(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def get_current_iv(url, token):
    response = encrypt_chosen_plaintext(
        plaintext=b"ff".hex(), token=token, url=url
    )
    iv = response.get("iv")
    return iv


def add_padding(word: bytes) -> int:
    padder = padding.PKCS7(128).padder()
    padded_word = padder.update(word)
    padded_word += padder.finalize()
    return padded_word


def test_padding():
    for i in range(1, 17):
        word = b"a" * i
        padded_word = add_padding(word)
        print(f"word: {word} ({len(word)} bytes)")
        print(f"padded_word: {padded_word.hex()}\n")


if __name__ == "__main__":
    host = "10.0.15.10"
    username = "stankovic_mateo"
    password = "bityconter"

    # Get the token
    path = "cbc/token"
    url = f"http://{host}/{path}"

    # Step 1: Get the token
    token = get_access_token(username, password, url)
    print(f"Token: {token}")

    # Step 2: Get the wordlist
    path = "static/wordlist.txt"
    url = f"http://{host}/{path}"

    wordlist = get_wordlist(url)

    # Step 3: Get the encrypted cookie and its IV
    path = "cbc/iv/encrypted_cookie"
    url = f"http://{host}/{path}"
    
    response = get_encrypted_cookie(url)
    ciphertext = Ciphertext(**response)
    cookie_iv = b64decode(ciphertext.iv)
    cookie_ciphertext = b64decode(ciphertext.ciphertext)

    cookie_iv = int.from_bytes(cookie_iv, byteorder="big")
    print(f"Cookie IV: {cookie_iv}")

    # Step 4: Get/learn the current IV
    path = "cbc/iv"
    url = f"http://{host}/{path}"

    iv = get_current_iv(url, token)
    current_iv = b64decode(iv)

    current_iv = int.from_bytes(current_iv, byteorder="big")
    print(f"Current IV: {current_iv}")

    # Step 5: Start the chosen-plaintext attack
    cookie = ""
    for word in wordlist.split():
        print(f"\nTesting word: {word}")
        
        # 5.1 Calculate the IV for the next word
        next_iv = current_iv + 4

        # 5.2 Pad the candidate word
        padded_word = add_padding(word)
        print(f"Padded word: {padded_word.hex()}")
        padded_word = int.from_bytes(padded_word, byteorder="big")

        # 5.3 Prepare chosen plaintext (hex encoded)
        chosen_plaintext = padded_word ^ cookie_iv ^ next_iv
        chosen_plaintext = chosen_plaintext.to_bytes(16, "big").hex()
        print(f"[*] Plaintext: {chosen_plaintext}") 

        # 5.4 Send the chosen plaintext to the server
        response = encrypt_chosen_plaintext(
            plaintext=chosen_plaintext,
            token=token,
            url=url,
        )
        
        ciphertext = Ciphertext(**response)
        iv = b64decode(ciphertext.iv)
        ciphertext = b64decode(ciphertext.ciphertext)        
        
        # 5.5 Verify if the candidate word matches the encrypted cookie
        if ciphertext[:16] == cookie_ciphertext[:16]:
            cookie = word.decode()
            print(f"Cookie: \t{cookie}")
           # break


        # 5.6 Update the current IV
        current_iv = int.from_bytes(iv, byteorder="big")
        print(f"[*] Current IV: {current_iv}")

        
    # Step 6: Derive the key from the cookie
    key = derive_key(key_seed=cookie)

    # Step 7: Get the challenge
    path = "cbc/iv/challenge"
    url = f"http://{host}/{path}"

    response = get_challenge(url)
    challenge = Challenge(**response)
    
    # Step 8: Decrypt the challenge
    plaintext = decrypt_challenge(key, challenge)
    print(f"\nDecrypted challenge: {plaintext}")