from threading import Thread
# AF_INET stands for IPv4, AF_INET6 stands for IPv6, SOCK_STREAM stands for TCP
from socket import socket, SOCK_STREAM
from ssl import PROTOCOL_TLS_SERVER, SSLContext
from .helpers import get_addr
import time


class Server(Thread):
    def __init__(self, host: str, port: str, max_conn=1, use_ssl=False, ssl_cert_location=None, ssl_cert_key_location=None, backlog=5) -> None:
        super().__init__()
        self.max_conn = max_conn
        self.conn_count = 0
        addr, addr_type = get_addr(host, port)
        self.socket = socket(addr_type, SOCK_STREAM)
        self.socket.bind((addr, port))
        self.socket.listen(backlog)
        if use_ssl:
            context = SSLContext(PROTOCOL_TLS_SERVER)
            context.load_cert_chain(ssl_cert_location, ssl_cert_key_location)
            self.socket = context.wrap_socket(self.socket)
        self.daemon = True
        self.conn_handler = lambda x, y: None
        self.__exception_cb = lambda x: None
        self.__challenge = None

    def run(self) -> None:
        try:
            while True:
                conn, addr = self.socket.accept()
                if self.max_conn != 0 and self.max_conn <= self.conn_count:
                    conn.send(b'REJECTED-NO_MORE_ROOM')
                    conn.close()
                    continue
                data = conn.recv(4096)
                if data == b'P2PCHAT-CLIENT-v0':
                    conn.send(b'P2PCHAT-ACK-v0')
                    if self.__challenge is not None:
                        conn.send(b'CHALLENGE-REQUIRED')
                        if self.__challenge(conn.recv(4096)):
                            self.conn_handler(conn, addr)
                            self.conn_count += 1
                        else:
                            conn.send(b'BAD-CHALLENGE')
                            conn.close()
                    else:
                        self.conn_handler(conn, addr)
                        self.conn_count += 1
                else:
                    conn.close()
        except Exception as e:
            self.__exception_cb(e)
            exit()

    def add_conn_handler(self, conn_handler):
        self.conn_handler = conn_handler

    def add_exception_cb(self, cb):
        self.__exception_cb = cb

    def set_challenge_handler(self, chall):
        self.__challenge = chall


class ClientConnection(Thread):
    def __init__(self, conn) -> None:
        super().__init__()
        self.socket = conn
        self.daemon = True
        self.__buffer = b''
        self.__msg = b''
        self.__msg_encrypt = False
        self.__msg_cb = lambda x, y: None
        self.__exception_cb = lambda x: None
        self.__last_send = int(time.time())

    def run(self) -> None:
        try:
            while True:
                buf = self.socket.recv(4096)
                if buf != b'\x00':
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
        if self.__last_send + 100 < int(time.time()):
            self.socket.send(b'\x00')

    def add_msg_callback(self, cb):
        self.__msg_cb = cb

    def add_exception_cb(self, cb):
        self.__exception_cb = cb
