# aes-gcm-siv-py

This is a Python reference implementation of CFRG Internet-Draft
"AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption".
Draft 9: November 19, 2018.
Tested with Python 2.

Do not use.

# Usage

    from reference import AES_GCM_SIV
    obj = AES_GCM_SIV(key, nonce)
    obj.encrypt(plaintext, aad)
    ...
    obj.decrypt(ciphertext, aad)

# License

This code is placed in the public domain.
