# -*- coding: utf-8 -*-
# Copyright (c) Bjorn Edstrom <be@bjrn.se> 2019

# Reference implementation of AES-GCM-SIV based on the IRTF draft.
# Do not use.


import Crypto.Cipher.AES as AES
import struct


class Field(object):
    # The field is defined by the irreducible polynomial
    # x^128 + x^127 + x^126 + x^121 + 1
    _MOD = sum((1 << a) for a in [0, 121, 126, 127, 128])

    # x^-128 is equal to x^127 + x^124 + x^121 + x^114 + 1
    _INV = sum((1 << a) for a in [0, 114, 121, 124, 127])

    @staticmethod
    def add(x, y):
        assert x < (1 << 128)
        assert y < (1 << 128)
        return x ^ y

    @staticmethod
    def mul(x, y):
        assert x < (1 << 128), x
        assert y < (1 << 128), y

        res = 0
        for bit in range(128):
            if (y >> bit) & 1:
                res ^= (2 ** bit) * x

        return Field.mod(res, Field._MOD)

    @staticmethod
    def dot(a, b):
        return Field.mul(Field.mul(a, b), Field._INV)

    @staticmethod
    def mod(a, m):
        m2 = m
        i = 0
        while m2 < a:
            m2 <<= 1
            i += 1
        while i >= 0:
            a2 = a ^ m2
            if a2 < a:
                a = a2
            m2 >>= 1
            i -= 1
        return a


def polyval(h, xs):
    """POLYVAL takes a field element, H, and a series of field elements X_1,
   ..., X_s.  Its result is S_s, where S is defined by the iteration S_0
   = 0; S_j = dot(S_{j-1} + X_j, H), for j = 1..s"""
    s = 0
    for x in xs:
        s = Field.dot(Field.add(s, x), h)
    return s


def b2i(s):
    res = 0
    for c in reversed(s):
        res <<= 8
        res |= ord(c)
    return res


def i2b(i):
    if i == 0:
        return '\x00'*16
    s = ''
    while i:
        s += chr(i & 0xff)
        i >>= 8
    return s


def s2i(s):
    return b2i(s.decode('hex'))


def i2s(i):
    return i2b(i).encode('hex')


def le_uint32(i):
    return struct.pack('<L', i)


def read_le_uint32(b):
    return struct.unpack('<L', b[0:4])[0]


def le_uint64(i):
    return struct.pack('<Q', i)


def split16(s):
    return [s[i:i+16] for i in range(0, len(s), 16)]


class AES_GCM_SIV(object):
    def __init__(self, key_gen_key, nonce):
        aes_obj = AES.new(key_gen_key)
        msg_auth_key = aes_obj.encrypt(le_uint32(0) + nonce)[0:8] + \
                       aes_obj.encrypt(le_uint32(1) + nonce)[0:8]
        msg_enc_key = aes_obj.encrypt(le_uint32(2) + nonce)[0:8] + \
                      aes_obj.encrypt(le_uint32(3) + nonce)[0:8]
        if len(key_gen_key) == 32:
            msg_enc_key += aes_obj.encrypt(le_uint32(4) + nonce)[0:8] + \
                           aes_obj.encrypt(le_uint32(5) + nonce)[0:8]
        self.msg_auth_key = msg_auth_key
        self.msg_enc_key = msg_enc_key
        self.nonce = nonce

    def _right_pad_to_16(self, inp):
        while len(inp) % 16 != 0:
            inp += '\x00'
        return inp

    def _aes_ctr(self, key, initial_block, inp):
        block = initial_block
        output = ''
        while len(inp) > 0:
            keystream_block = AES.new(key).encrypt(block)
            block = le_uint32((read_le_uint32(block[0:4]) + 1) & 0xffffffff) + block[4:]
            todo = min(len(inp), len(keystream_block))
            for j in range(todo):
                output += chr(ord(keystream_block[j]) ^ ord(inp[j]))
            inp = inp[todo:]
        return output

    def encrypt(self, plaintext, additional_data):
        """Encrypt"""

        if len(plaintext) > 2**36:
            raise ValueError('plaintext too large')

        if len(additional_data) > 2**36:
            raise ValueError('additional_data too large')

        length_block = le_uint64(len(additional_data) * 8) + \
                       le_uint64(len(plaintext) * 8)

        padded_plaintext = self._right_pad_to_16(plaintext)
        padded_ad = self._right_pad_to_16(additional_data)

        S_s = polyval(b2i(self.msg_auth_key),
                      map(b2i, split16(padded_ad) + split16(padded_plaintext) + [length_block]))
        S_s = i2b(S_s)
        S_s = bytearray(S_s)
        nonce = bytearray(self.nonce)

        for i in range(12):
            S_s[i] ^= nonce[i]
        S_s[15] &= 0x7f

        tag = AES.new(self.msg_enc_key).encrypt(bytes(S_s))
        counter_block = bytearray(tag)
        counter_block[15] |= 0x80

        return self._aes_ctr(self.msg_enc_key, bytes(counter_block), plaintext) + bytes(tag)

    def decrypt(self, ciphertext, additional_data):
        """Decrypt"""

        if len(ciphertext) < 16 or len(ciphertext) > 2**36 + 16:
            raise ValueError('ciphertext too small or too large')

        if len(additional_data) > 2**36:
            raise ValueError('additional_data too large')

        ciphertext, tag = ciphertext[0:-16], ciphertext[-16:]

        counter_block = bytearray(tag)
        counter_block[15] |= 0x80
        plaintext = self._aes_ctr(self.msg_enc_key, bytes(counter_block), ciphertext)

        length_block = le_uint64(len(additional_data) * 8) + \
                       le_uint64(len(plaintext) * 8)

        padded_plaintext = self._right_pad_to_16(plaintext)
        padded_ad = self._right_pad_to_16(additional_data)

        #
        S_s = polyval(b2i(self.msg_auth_key),
                      map(b2i, split16(padded_ad) + split16(padded_plaintext) + [length_block]))
        S_s = i2b(S_s)
        S_s = bytearray(S_s)
        nonce = bytearray(self.nonce)
        for i in range(12):
            S_s[i] ^= nonce[i]
        S_s[15] &= 0x7f

        #
        expected_tag = bytearray(AES.new(self.msg_enc_key).encrypt(bytes(S_s)))
        actual_tag = bytearray(tag)

        xor_sum = 0
        for i in range(len(expected_tag)):
            xor_sum |= expected_tag[i] ^ actual_tag[i]

        if xor_sum != 0:
            raise ValueError('auth fail')

        return plaintext
