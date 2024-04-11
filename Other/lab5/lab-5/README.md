# Lab 5: Randomized encryption (CBC mode)

## Recovered Challenge

Decrypted challenge: **Chuck Norris doesn't use Oracle, he is the Oracle. (CTR: oheparmert)**

### Username and Password

---
**NOTE**

Password je iz proslog Recovered Challenge

---

| username          | password     |
| :---------------- | :----------- |
| `stankovic_mateo` | `bityconter` |


### Dohavtiti Token

| Token                                                                                                                                                          |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdGFua292aWNfbWF0ZW8iLCJzY29wZSI6ImNiYyIsImV4cCI6MTcxMjIxODIyM30.5axfmMpuhDKZndhg-3-SC-cm9N2KGRhf8hFGV7t0mdA` |


---
**INFO**

| Tko šalje | Što šalje                                                                                    | Napomena                                                               |
| :-------- | :------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------- |
| V → S     | p<sub>V</sub> = `yes` or `no`                                                                | over secure channel                                                    |
| S → DB    | IV<sub>V</sub>, C<sub>V</sub> = E<sub>K</sub>(p<sub>V</sub> \|\| `padding` ⊕ IV<sub>V</sub>) | over channel using CBC encryption                                      |
| A → S     | p<sub>A</sub> = `yes` \|\| `padding` ⊕  IV<sub>V</sub> ⊕  IV<sub>next</sub>                  | attacker A can predict IV<sub>next</sub>                               |
| S → DB    | IV<sub>next</sub>, C<sub>A1</sub> = E<sub>K</sub>(p<sub>A</sub> ⊕ IV<sub>next</sub>)         | over CBC channel, C<sub>A1</sub> 1st ciphertext block of C<sub>A</sub> |

Napadač _A_ zna sljedeće javne informacije: 

1. zna da je žrtva odabrala `yes` ili `no`
2. zna IV<sub>V</sub> i C<sub>V</sub> jer ih server šalje javnim kanalom
3. može predvidjeti IV<sub>next</sub>
4. zna C<sub>A1</sub> (prvi ciphertext block) jer ih server šalje javnim kanalom

---


