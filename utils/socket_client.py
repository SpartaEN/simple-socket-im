from threading import Thread
# AF_INET stands for IPv4, AF_INET6 stands for IPv6, SOCK_STREAM stands for TCP
from socket import socket, SOCK_STREAM, SHUT_RDWR
from ssl import PROTOCOL_TLS_CLIENT, SSLContext
from .helpers import get_addr, HandshakeError
import time

'''
NOTE: All length fields are in little endian 
Protocol Spec Version 0:
Handshake: C -> S: P2PCHAT-CLIENT-v0
           S -> C: P2PCHAT-ACK-v0
    If use encrypt:
            S -> C: CHALLENGE-REQUIRED
            C -> S: CHALLENGE-ACCEPTED-<NONCE-1> (encrypted by aes-256-cbc)
General unencrypted payload:
| 0x01 | 4 bytes length | payload |
General encrypted payload:
| 0x02 | 4 bytes length | 16 bytes IV | encrypted payload |


    While the encrypted msg contains extra msg:
    | 0xdaedbeef (Validation purpose) | 4 bytes counter | other msg |
    Message:
    | 0x00 | 1 byte length | username |
    | 0x01 | 4 bytes length | msg |
    Direct file send (Unsafe, meanwhile, not available in groupchat):
    | 0x05 | 1 byte file name | 4 bytes file length | file data | 
    End chat
    | 0x06 |

    Groupchat Auth
    | 0x21 | 0x01 | 1 byte username length | username | 1 byte password length | password |
    Groupchat Session
    | 0x21 | 0x02 | 0x01 for success 0x00 for fail | Session ID/Reason |
    Groupchat Msg out
    | 0x22 | 1 byte session id length | session id | 4 bytes msg length | message |
    Groupchat Msg in
    | 0x23 | 1 byte username length | username | 4 bytes msg length | message |
    Groupchat System notification
    | 0x24 | 4 bytes msg length | message |
    Groupchat get online users
    | 0x25 | 1 byte session id length | session id |
    End group chat
    | 0x06 | 1 byte session id length | session id |

    The following section will not be implemented:
        File send request:
        | 0x02 | 1 byte file name | filename | 2 bytes secret |
        File accept:
        | 0x03 | 2 bytes secret |
        File data:
        | 0x04 | 4 bytes length | file data |

    Tracker register:
    | 0x10 | 2 bytes length for username | username | 2 bytes length for password | password | 
    General payload for tracker authenication:
    | 2 bytes length for username | username | 2 bytes length for password | password |
    Update tracker DB:
    | 0x11 | General authenication | 2 bytes length for address | address | port (2 bytes) | 1 byte key length | key | 2 bytes description | description | 0x01/0x00 for specific user | 1 byte username length | username |
    Get available chats:
    | 0x12 | General authenication | 2 bytes entry length | entries |
        Entry:
        | 1 byte description length | description | 2 bytes length for address | address | port (2 bytes) | 1 byte key length | key |

Heartbeat msg:
| 0x00 |
'''


class Client(Thread):
    def __init__(self, host: str, port: str, use_ssl=False, ssl_cert_location=None) -> None:
        super().__init__()
        addr, addr_type = get_addr(host, port)
        self.socket = socket(addr_type, SOCK_STREAM)
        self.socket.connect((addr, port))
        if use_ssl:
            context = SSLContext(PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(ssl_cert_location)
            context.check_hostname = False
            self.socket = context.wrap_socket(self.socket)
        self.socket.send(b'P2PCHAT-CLIENT-v0')
        if self.socket.recv(4096) != b'P2PCHAT-ACK-v0':
            raise HandshakeError()
        self.daemon = True
        self.__buffer = b''
        self.__msg = b''
        self.__msg_encrypt = False
        self.__msg_cb = lambda x, y: None
        self.__exception_cb = lambda x: None
        self.__challenge = None
        self.__verified = False
        self.__last_send = int(time.time())
        self.__is_down = False

    def run(self) -> None:
        try:
            while True:
                if self.__is_down:
                    break
                buf = self.socket.recv(4096)
                if len(buf) == 0:
                    continue
                if buf == b'CHALLENGE-REQUIRED' and self.__verified == False:
                    if self.__challenge is None:
                        raise HandshakeError(
                            'Server is expecting an challenge')
                    self.socket.send(self.__challenge())
                    continue
                if buf == b'BAD-CHALLENGE' and self.__verified == False:
                    raise HandshakeError('Challenge Failed.')
                if buf != b'\x00':
                    self.__verified = True
                    self.__buffer += buf
                    msg_len = int.from_bytes(
                        self.__buffer[1:5], byteorder='little')
                    if msg_len <= len(self.__buffer) + 5:
                        self.__msg = self.__buffer[5:5+msg_len]
                        self.__msg_encrypt = self.__buffer[0] == 2
                        self.__buffer = self.__buffer[5+msg_len:]
                        self.__msg_cb(self.__msg, self.__msg_encrypt)
        except Exception as e:
            self.__exception_cb(e)
            exit()

    def get_msg(self):
        return (self.__msg_encrypt, self.__msg)

    def send_msg(self, msg: bytes, encrypt=False) -> None:
        self.__last_send = int(time.time())
        if not encrypt:
            self.socket.send(b'\x01' + (len(msg)).to_bytes(4, 'little') + msg)
        else:
            self.socket.send(b'\x02' + (len(msg)).to_bytes(4, 'little') + msg)

    def send_keep_alive(self):
        if self.socket.fileno() == -1:
            return False
        if self.__last_send + 100 < int(time.time()):
            self.socket.send(b'\x00')
        return True

    def add_msg_callback(self, cb):
        self.__msg_cb = cb

    def add_exception_cb(self, cb):
        self.__exception_cb = cb

    def set_challenge_handler(self, handler):
        self.__challenge = handler

    def shutdown(self):
        self.__is_down = True
        self.socket.shutdown(SHUT_RDWR)
        self.socket.close()
