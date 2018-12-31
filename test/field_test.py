import unittest

from reference import Field, i2s, s2i


class PolyvalTest(unittest.TestCase):
    def setUp(self):
        self.a = s2i(b'66e94bd4ef8a2c3b884cfa59ca342b2e')
        self.b = s2i(b'ff000000000000000000000000000000')

    def test_add(self):
        assert i2s(Field.add(self.a, self.b)) == b'99e94bd4ef8a2c3b884cfa59ca342b2e'

    def test_mul(self):
        assert i2s(Field.mul(self.a, self.b)) == b'37856175e9dc9df26ebc6d6171aa0ae9'

    def test_dot(self):
        assert i2s(Field.dot(self.a, self.b)) == b'ebe563401e7e91ea3ad6426b8140c394'


if __name__ == '__main__':
    unittest.main()
