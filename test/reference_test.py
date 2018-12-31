import unittest

from reference import AES_GCM_SIV, s2i, i2s


class ReferenceTest(unittest.TestCase):
    def _test_encrypt(self, pt, aad, key, nonce, result):
        obj = AES_GCM_SIV(key.decode('hex'), nonce.decode('hex'))
        assert result == obj.encrypt(pt.decode('hex'), aad.decode('hex')).encode('hex')

    def _test_decrypt(self, pt, aad, key, nonce, result):
        obj = AES_GCM_SIV(key.decode('hex'), nonce.decode('hex'))
        assert pt == obj.decrypt(result.decode('hex'), aad.decode('hex')).encode('hex')

    def _test(self, pt, aad, key, nonce, result):
        self._test_encrypt(pt, aad, key, nonce, result)
        self._test_decrypt(pt, aad, key, nonce, result)

    def test_128_1(self):
        pt = ''
        aad = ''
        key = '01000000000000000000000000000000'
        nonce = '030000000000000000000000'
        result = 'dc20e2d83f25705bb49e439eca56de25'
        self._test(pt, aad, key, nonce, result)

    def test_128_2(self):
        pt = '0100000000000000'
        aad = ''
        key = '01000000000000000000000000000000'
        nonce = '030000000000000000000000'
        result = 'b5d839330ac7b786578782fff6013b815b287c22493a364c'
        self._test(pt, aad, key, nonce, result)

    def test_128_3(self):
        pt = '010000000000000000000000'
        aad = ''
        key = '01000000000000000000000000000000'
        nonce = '030000000000000000000000'
        result = '7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639'
        self._test(pt, aad, key, nonce, result)

    def test_256_1(self):
        pt = ''
        aad = ''
        key = '0100000000000000000000000000000000000000000000000000000000000000'
        nonce = '030000000000000000000000'
        result = '07f5f4169bbf55a8400cd47ea6fd400f'
        self._test(pt, aad, key, nonce, result)

    def test_256_2(self):
        pt = '020000000000000000000000'
        aad = '01'
        key = '0100000000000000000000000000000000000000000000000000000000000000'
        nonce = '030000000000000000000000'
        result = '163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f'
        self._test(pt, aad, key, nonce, result)

    def test_256_3(self):
        pt = 'c9882e5386fd9f92ec'
        aad = '489c8fde2be2cf97e74e932d4ed87d'
        key = 'd1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0'
        nonce = '9f572c614b4745914474e7c7'
        result = '0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2'
        self._test(pt, aad, key, nonce, result)

    def test_256_4(self):
        pt = 'ced532ce4159b035277d4dfbb7db62968b13cd4eec'
        aad = '734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541'
        key = '3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23'
        nonce = '688089e55540db1872504e1c'
        result = '626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594'
        self._test(pt, aad, key, nonce, result)

    def test_counter_wrap_1(self):
        pt = '000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108'
        aad = ''
        key = '0000000000000000000000000000000000000000000000000000000000000000'
        nonce = '000000000000000000000000'
        result = 'f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3eaffffffff000000000000000000000000'
        self._test_encrypt(pt, aad, key, nonce, result)

    def test_counter_wrap_2(self):
        pt = 'eb3640277c7ffd1303c7a542d02d3e4c0000000000000000'
        aad = ''
        key = '0000000000000000000000000000000000000000000000000000000000000000'
        nonce = '000000000000000000000000'
        result = '18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff000000000000000000000000'
        self._test_encrypt(pt, aad, key, nonce, result)


if __name__ == '__main__':
    unittest.main()
