import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from .helpers import MessageExpirationError, InvalidMessageError, gen_nonce


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
        self.counter_rx = -1
        self.counter_tx = 0

    def encrypt(self, raw):
        # In case of replay attack
        # Add magic to verify message is valid
        raw = self._pad(b'\xde\xad\xbe\xef' +
                        int(self.counter_tx).to_bytes(4, 'little') + raw)
        self.counter_tx += 1
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        m = self._unpad(cipher.decrypt(enc[AES.block_size:]))
        if len(m) < 8 or m[0:4] != b'\xde\xad\xbe\xef':
            raise InvalidMessageError
        counter = int.from_bytes(m[4:8], 'little')
        if self.counter_rx >= counter:
            raise MessageExpirationError(self.counter_rx + 1, counter)
        self.counter_rx = counter
        return m[8:]

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * (self.bs - len(s) % self.bs).to_bytes(1, 'little')

    def client_challenge_construct(self):
        return self.encrypt(b'CHALLENGE-ACCEPTED-'+gen_nonce())

    def server_challenge_verify(self, msg):
        if self.decrypt(msg)[0:18] == b'CHALLENGE-ACCEPTED':
            return True
        else:
            return False

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
