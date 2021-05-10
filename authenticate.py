import requests
import re
import typing
import hashlib
import base64
import argparse
import sys

import tp_link_crypto


DEBUG: bool = False
USERNAME: str = "admin"  # Hardcoded in the router
USER_AGENT: str = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0"
AES_KEY: str = "A" * 16
AES_IV: str = "B" * 16


def print_d(msg: str) -> None:
    if DEBUG:
        print(msg)


def is_supported_model(ip_addr: str) -> bool:
    """
    Determines if a router is supported.
    :param ip_addr: IP address of the router
    :return: True if supported, otherwise False
    """
    # Tuples of model name and model description
    supported_models = [
        ("Archer C20", "AC750 Wireless Dual Band Router ")  # The space at the end of the model desc is intentional
    ]

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Update-Insecure-Request": "1",
    }
    r = requests.post(f"http://{ip_addr}/", headers=headers)
    print_d(r.text)

    # Parse the response for the model name and model description
    match = re.search(r"modelName=\"([a-zA-Z0-9 ]+)\"", r.text)
    if not match:
        print("[-] Could not find the router's model name")
        return False
    model_name: str = match.group(1)
    match = re.search(r"modelDesc=\"(.+)\"", r.text)
    if not match:
        print("[-] Could not find the router's model description")
        return False
    model_desc: str = match.group(1)

    # Determine if it's in the list of supported models
    for supported_model in supported_models:
        if supported_model[0] in model_name and supported_model[1] in model_desc:
            print(f"[+] Found supported device: {model_name} {model_desc}")
            return True

    print(f"[-] Model name \"{model_name}\" and model description \"{model_desc}\" is not supported")
    return False


def get_rsa_public_key(s: requests.Session, ip_addr: str) -> typing.Union[typing.Tuple[int, int, int], None]:
    """
    Requests the public key and sequence from the router.
    :param s: The active HTTP session with the router.
    :param ip_addr: The router's IP address
    :return: A tuple of RSA e and n values with the sequence number on success, otherwise None
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Origin": f"http://{ip_addr}",
        "Connection": "keep-alive",
        "Referer": f"http://{ip_addr}",
        "Accept-Language": "en-US,en;q=0.5",
    }
    data = "[/cgi/getParm#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
    resp = s.post(f"http://{ip_addr}/cgi?8", headers=headers, data=data)

    # On success, response should look like the following:
    #
    # ```
    # [cgi]0
    # var ee="010001";
    # var nn="CB8FD67593B228445BBB882ED34B0787AF19AF3F6BE73793AC64BC64D3C4C41EBD149599F5801848DF92C244749DB07834789060B420979377D24DF7C7E437EB";
    # var seq="690699493";
    # $.ret=0;
    # [error]0
    # ```
    print_d(resp.headers)
    print_d(resp.text)

    # Get the RSA public key (i.e. n and e values)
    match = re.search("nn=\"(.+)\"", resp.text)
    if not match:
        print("[-] Could not find RSA n value in get RSA public key response")
        return None
    n_bytes = match.group(1)
    print(f"[+] RSA n: {n_bytes}")
    match = re.search("ee=\"(.+)\"", resp.text)
    if not match:
        print("[-] Could not find RSA e value in get RSA public key response")
        return None
    e_bytes = match.group(1)
    print(f"[+] RSA e: {e_bytes}")

    # Get the sequence. This is set to sequence += data_len and verified server-side.
    match = re.search("seq=\"(.+)\"", resp.text)
    if not match:
        print("[-] Could not find seq value in get RSA public key response")
        return None
    seq_bytes = match.group(1)
    print(f"[+] Sequence: {seq_bytes}")

    e = int(e_bytes, 16)
    n = int(n_bytes, 16)
    seq = int(seq_bytes, 10)

    return e, n, seq


def authenticate(s: requests.Session, ip_addr: str, password: str) -> bool:
    """
    Authenticates with the TP-Link router.
    :param s: The active requests session
    :param ip_addr: The router's IP address
    :param password: The password to the router's web server
    :return: True on success, otherwise False
    """
    # Get the RSA public key parameters and the sequence
    rsa_vals = get_rsa_public_key(s, ip_addr)
    if rsa_vals is None:
        print("[-] Failed to get RSA public key and sequence values")
        return False
    e, n, seq = rsa_vals

    # Create the data field
    aes_key = AES_KEY.encode("utf-8")
    aes_iv = AES_IV.encode("utf-8")
    login_data: str = f"8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername={USERNAME}\r\npassword={password}\r\n"
    data_ciphertext = tp_link_crypto.aes_encrypt(aes_key, aes_iv, login_data.encode())
    data = base64.b64encode(data_ciphertext).decode()
    print_d(login_data)

    # Create the sign field
    seq_with_data_len = seq + len(data)
    auth_hash = hashlib.md5(f"{USERNAME}{password}".encode()).digest()
    # The string __must__ be null terminated, otherwise strlen gets the wrong size
    print(f"[*] Setting AES key to {AES_KEY}")
    print(f"[*] Setting AES IV to {AES_IV}")
    plaintext = f"key={AES_KEY}&iv={AES_IV}&h={auth_hash.hex()}&s={seq_with_data_len}\x00\r\n"
    sign = tp_link_crypto.rsa_encrypt(e, n, plaintext.encode())
    print_d(plaintext)

    # Send the authentication request
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "text/plain",
        "Accept": "*/*",
        "Origin": f"http://{ip_addr}",
        "Connection": "keep-alive",
        "Referer": f"http://{ip_addr}/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
    }
    request_data = f"sign={sign.hex()}\r\ndata={data}\r\n"
    resp = s.post(f"http://{ip_addr}/cgi_gdpr", headers=headers, data=request_data)

    # Get the session cookie
    cookie = resp.headers["Set-Cookie"]
    if cookie is None:
        print("[-] Login response did not include a Set-Cookie field in the header")
        return False
    # Example of the cookie field:
    # ```
    # JSESSIONID=fc1e35a7a860e860be66d44bc7b34e; Path=/; HttpOnly
    # ```
    # Get the JSESSIONID field because it's used during other requests.
    match = re.search(r"JSESSIONID=([a-z0-9]+)", cookie)
    if not match:
        print("[-] Could not find the JSESSIONID in the Set-Cookie filed of the login response")
        return False
    jsessionid = match.group(1)
    print(f"[+] JSESSIONID: {jsessionid}")

    # Decode the Base64 encoded response
    decoded: bytes = base64.b64decode(resp.text)
    decrypted_resp = tp_link_crypto.aes_decrypt(aes_key, aes_iv, decoded)

    # Remove the PKCS #7 padding
    num_padding_bytes = int(decrypted_resp[-1])
    decrypted_resp = decrypted_resp[:-num_padding_bytes]

    decrypted_resp_str: str = decrypted_resp.decode()
    print_d(decrypted_resp_str)
    if "[cgi]0" in decrypted_resp_str and "$.ret=0" in decrypted_resp_str and "[error]0" in decrypted_resp_str:
        print("[+] Successfully authenticated with the router")
    else:
        # This might not be an error because other routers may have different response codes. The Archer C20 returns:
        # ```
        # [cgi]0
        # $.ret=0;
        # [error]0
        # ```
        print("[-] Unknown response message from router")
        print(decrypted_resp_str)

    return True


def main(ip_addr: str, password: str) -> int:
    print(f"[*] Connecting to router at {ip_addr}")

    if not is_supported_model(ip_addr):
        print("[-] Router is not supported")
        return 1

    s = requests.Session()
    success = authenticate(s, ip_addr, password)
    if not success:
        print("[-] Could not authenticate with the router")
        s.close()
        return 1
    s.close()

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip_address", type=str)
    parser.add_argument("password", type=str)
    args = parser.parse_args()

    sys.exit(main(args.ip_address, args.password))
