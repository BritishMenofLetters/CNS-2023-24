# Lab 7: Public key cryptography (RSA, Diffie-Hellman)

## Recovered Challenge

Decrypted challenge: **The square root of Chuck Norris is pain. Do not try to square Chuck Norris, the result is death.**

### Username and Password

---
**NOTE**

Password je iz proslog Recovered Challenge

"nonce" - _broj koji se koristi jednom_ (služi kao counter)

Ne smije se dogoditi ista kombinacija nonce i key

---

| username          | password     |
| :---------------- | :----------- |
| `stankovic_mateo` | `pofriopris` |

### Dohavtiti Token

| Token                                                                                                                                                                   |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdGFua292aWNfbWF0ZW8iLCJzY29wZSI6ImFzeW1tZXRyaWMiLCJleHAiOjE3MTUyNDE3NjB9.kwzRIxeGnHy1p6yvUa7yXcy-8FsPLP1RKe3c5lhGcsU` |


| Plaintext                                                                                                                                                                                         |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |

| Decryption key:                                                                          |
| :--------------------------------------------------------------------------------------- |
| "\x9a\xc8}\xdd`\x9d\xc8=\x9f8y\x7f\x02d\xa1\xd77\xf1\x13z'\xb4FK*\xc1;B\x9a\xf5\xc3\x1e" |

  **NOTE**
  
  `Decyption key` je ***fb*** string (length:256).

| Established shared key:                                                                                                                                                     |
| :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ":\x88\xac\xfc\xef-\xf4\x91\x89P\xff\xe4\xdaed\xcc\xae\x177j \xe1\xa2\xb4\xd3M\xd7\x19Y\xa5\xc4#2\x1a\xf9x\xfe6\xef!\x87!\x1f2\xfb\x11\x1c\x99\xaf\xef\xa9\x03\xb0\xec\xd3r | D\x15\xfa\\\xcf\xbc\n\x8bp\xce\xa4`\x9e\x11)\x02]\x0es\x8f\xff\x00g\x95-\xec\x0c\x7f\xb6\n\xb1\x07\xc7k\x0e1\xa2\x15[\x08\xc9\x89'\r\xa4\xeb\xf6F#\xbb\xb0\xadQX)\xeaV\xfbl!\x91\xbeiD\xf9\xffF[d@\xaa\x9b\xa8\xfbfK\xd3\xa9U\xe2\xd2\xcf\xb7\xec8\xce\xe9\x14b\x11\xd2E\xf9\x928B\xc8D\x85\xc6\x98U\x1f\x03\x070If\x19\xb7B/\xdb | \xd8\x7f\xa5\x92r\xa7\xc1 YO:\x84r\xd9\x16\xe2\xec\x13]\x9etDVN\x97\xcf\x05\x9d\x94\xc4@\x9c | f\xefv\n\xbeG\x06y\xdf\xa6\x8b\xc8\xbc\xb9rq<\x8b\x13\xfda\x17\x08\x94\xabB\xe2<\xcb\x94\x94\xdc$\xebr!\x04 | \xa0\xde,Yi\xc1\x7f\x90/Vd0\x97\xd6" |

  **NOTE**
  
  `Decyption key` je ***b*** string (length:256).
