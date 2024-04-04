import requests
from pydantic import BaseModel
from base64 import b64decode
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class Ciphertext(BaseModel):
    iv: str
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
        url=url, token=token, plaintext=b"dummy".hex())
    return response.get("iv")


if __name__ == '__main__':
    host = "10.0.15.6"
    username = "celan_dea"

    # get the token
    path = "cbc/token"
    url = f"http://{host}/{path}"
    password = "froneporan"

    token = get_token(url, username, password)
    print(f"Token: {token}")

    # Get the wordlist
    path = "static/wordlist.txt"
    url = f"http://{host}/{path}"
    wordlist = get_wordlist(url)

    # Get the encrypted cookie and its IV
    path = "cbc/iv/encrypted_cookie"
    url = f"http://{host}/{path}"
    response = get_encrypted_cookie(url)
    ciphertext = Ciphertext(**response)
    cookie_iv = b64decode(ciphertext.iv)
    cookie_ciphertext = b64decode(ciphertext.ciphertext)

    cookie_iv = int.from_bytes(cookie_iv, byteorder="big")
    print(f"Cookie IV: {cookie_iv}")

    # Get current IV
    path = "cbc/iv/"
    url = f"http://{host}/{path}"
    current_iv = get_current_iv(url, token)
    current_iv = b64decode(current_iv)
    current_iv = int.from_bytes(current_iv, byteorder="big")
    print(f"Current IV: {current_iv}")

    # Prepare chosen plaintext and start CPA
    cookie = ""
    for word in wordlist.split():
        print(f"\nTesting word: {word}")
        next_iv = current_iv + 4

        padded_word = add_padding(word)
        print(f"Padded word: {padded_word.hex()}")
        padded_word = int.from_bytes(padded_word, byteorder="big")

        chosen_plaintext = padded_word ^ cookie_iv ^ next_iv
        chosen_plaintext = chosen_plaintext.to_bytes(16, "big").hex()
        response = encrypt_chosen_plaintext(
            url=url, token=token, plaintext=chosen_plaintext
        )
        ciphertext = Ciphertext(**response)
        iv = b64decode(ciphertext.iv)
        ciphertext = b64decode(ciphertext.ciphertext)

        if ciphertext[:16] == cookie_ciphertext[:16]:
            cookie = word.decode()
            print(f">>>>>>> Cookie: {cookie}")
            break
        current_iv = int.from_bytes(iv, byteorder="big")

    # Get the challenge
    path = "cbc/iv/challenge"
    url = f"http://{host}/{path}"
    response = get_challenge(url)
    challenge = Challenge(**response)

    # derive the decryption key
    key = derive_key(cookie)

    # decrypt the challenge
    plaintext = decrypt_challenge(key, challenge)
    print(f"Decrypted challenge: {plaintext}")
