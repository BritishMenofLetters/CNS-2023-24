# Lab 2: Man-in-the-middle attack

Ranjivost Address Resolution Protocol-a (ARP) omogućava Man in the Middle (MitM) - napad na računala koja dijele zajedničku lokalnu mrežu (LAN, WLAN)

## ARP spoofing

## Recovered Challenge

username=stankovic_mateo&password=sttsarsher

"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdGFua292aWNfbWF0ZW8iLCJzY29wZSI6ImFycCIsImV4cCI6MTcxMTAxNDg3Nn0.jmbDYzOmyyYYNqIgHfGLc_W_pOznXj_mY1s2uYbDgz4"

"cookie": "pstteiteindkucie"

Key: b'`\xec@~\xe4\x96\xca\xbfM\x97\xbf\x82\x91T\x14\xd0,u\xb5\x18\xeb\xb4\xd0\x17Dr\x01)C\xcat\xfc'

### Decrypted challenge: 

**Chuck Norris does not code in cycles, he codes in strikes. (VERNAM: chitsolyeo)**

## IP header

Crypto oracle(IP):  10.0.15.17
Crypto oracle(MAC): 02:42:0a:00:0f:11

ARP client(IP):     10.0.15.39
ARP client(MAC):    02:42:0a:00:0f:27

Attacker(IP):       10.0.15.18
Attacker(MAC):      02:42:0a:00:0f:12

### IP header before & after the attack:

 |               | `MAC`<sub>src</sub> | `MAC`<sub>dst</sub> | `IP`<sub>src</sub> | `IP`<sub>dst</sub> | `payload`         |
 | :------------ | :------------------ | :------------------ | :----------------- | :----------------- | :---------------- |
 | before attack | `02:42:0a:00:0f:27` | `02:42:0a:00:0f:11` | `10.0.15.39`       | `10.0.15.17`       | username&password |
 | after attack  | `02:42:0a:00:0f:27` | `02:42:0a:00:0f:12` | `10.0.15.39`       | `10.0.15.17`       | username&password |

### username&pasword
| username        | password   |
| :-------------- | :--------- |
| stankovic_mateo | sttsarsher |

## Lab Preparation Questions

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdGFua292aWNfbWF0ZW8iLCJzY29wZSI6ImFycCIsImV4cCI6MTcxMTAxNDg3Nn0.jmbDYzOmyyYYNqIgHfGLc_W_pOznXj_mY1s2uYbDgz4",
  "token_type": "bearer"
}

"cookie": "pstteiteindkucie"

{
  "iv": "pZTGkjyucR3HNgb29jZiig==",
  "ciphertext": "kmAGVSPR2DgN9HYSTZdRDcWkiKfQDQSq+u0ZsbCImuM6nOrdTIW0uVGasqEJbxPXi8MW6fEsDQYrkHNBC4S26D9cXJ8mQq8YPe7XLsR2nW8="
}

Decrypted challenge: Chuck Norris does not code in cycles, he codes in strikes. (VERNAM: chitsolyeo)