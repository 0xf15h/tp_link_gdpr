import binascii
import math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def rsa_encrypt(e: int, n: int, plaintext: bytes) -> bytes:
    """
    RSA encrypts plaintext. TP-Link breaks the plaintext down into 64 byte blocks and concatenates the output.
    :param e: The RSA public key's e value
    :param n: The RSA public key's n value
    :param plaintext: The data to encrypt
    :return: RSA encrypted ciphertext
    """
    rsa_block_size = 64  # This is set by the router
    # Align the input with the block size since PKCS1 padding is not used
    if len(plaintext) % rsa_block_size != 0:
        plaintext += b"\x00" * (rsa_block_size - (len(plaintext) % rsa_block_size))
    num_blocks = int(len(plaintext) / rsa_block_size)
    ciphertext = bytes()
    block_start = 1
    block_end = rsa_block_size
    for block_itr in range(num_blocks):
        # RSA encrypt manually because the cryptography package does not allow RSA without padding because it's unsafe
        plaintext_num = int.from_bytes(plaintext[block_start - 1:block_end], byteorder="big")
        ciphertext_num = pow(plaintext_num, e, n)
        ciphertext += ciphertext_num.to_bytes(math.ceil(n.bit_length() / 8), byteorder="big")
        block_start += rsa_block_size
        block_end += rsa_block_size
    return ciphertext


def test_rsa_encrypt():
    e = 0x10001
    n = 0xD1360056D6090AF5987BCD20FB6979279C7BDEF84D465EFEDE5BC0481D80A2B6980F78396567853B369DE1369E7E055C73740AFD9EAD337548E493340150F36B  # noqa
    plaintext = "key=1617857002547232&iv=1617857002547416&h=bb0f7e021d52a4e31613d463fc0525d8&s=271058692"
    ciphertext = rsa_encrypt(e, n, plaintext.encode())
    expected_ciphertext = binascii.a2b_hex(
        "1311e8009b3f52a4e3a74766a46ab1fda759914d72c214522c06d8174a14018ebb67689b1f5ded765bba3b33897c6fdfcca0ca06ebfafb"
        "510918b602c0036a99835a92669370909836c3edb33b9c6f140e4e863b18bd269fcdfec925ff1ee2e3df449fcc296483088c2209aab1b2"
        "3d1e8ff9211079986d67a64cb24395cc7c03"
    )
    assert ciphertext == expected_ciphertext, "ciphertext != expected ciphertext"


def aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    AES-CBC encrypt with PKCS #7 padding. This matches the AES options on TP-Link routers.
    :param key: The AES key
    :param iv: The AES IV
    :param plaintext: Data to encrypt
    :return: Ciphertext
    """
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    plaintext_bytes: bytes = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext


def test_aes_encrypt():
    plaintext: str = f"8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=password123\r\n"
    key_str = "1617893956394957"
    iv_str = "1617893957882902"
    ciphertext = aes_encrypt(key_str.encode(), iv_str.encode(), plaintext.encode())
    expected_ciphertext = binascii.a2b_hex(
        "cef65de70e822e2bbdfbd7e9fa4fa6ac3d821b130a71852d3c4b601832498067966f28234c5d0a4b1f96e9073fe72b2ba6a5e30c821a1f"
        "a779aa407e318cd0603e844b8872a387cfa1e37d0a1191ff3cf2a27ed5d2154955fb86932bac293b5c"
    )
    assert ciphertext == expected_ciphertext, "ciphertext != expected ciphertext"


def aes_decrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    AES-CBC decrypt with PKCS #7 padding.
    :param key: The AES key
    :param iv: The AES IV
    :param plaintext: Data to encrypt
    :return: Ciphertext
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    ciphertext = decryptor.update(plaintext) + decryptor.finalize()
    return ciphertext
