from socket import AF_INET, AF_INET6, getaddrinfo, gaierror
from threading import Thread
from time import sleep
import random


def get_addr(host: str, port: int):
    addr = None
    addr_type = None
    # Prefer IPv6
    try:
        addr = getaddrinfo(host, port, AF_INET)[0][4][0]
        addr_type = AF_INET
    except gaierror:
        pass
    try:
        addr = getaddrinfo(host, port, AF_INET6)[0][4][0]
        addr_type = AF_INET6
    except gaierror:
        pass
    if addr != None:
        return (addr, addr_type)
    raise gaierror('No address found!')


def gen_nonce():
    return random.randint(0x10000000, 0xffffffff).to_bytes(4, 'little')


def keep_alive(conn, exception_handler):
    def run(conn, exception_handler):
        try:
            while True:
                sleep(180)
                conn.send(b'\x00')
        except Exception as e:
            exception_handler(e)
            exit()
    Thread(target=run, args=(conn, exception_handler), daemon=True).start()


def gen_secret(l=5):
    table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    res = ''
    for i in range(0, l):
        res += table[random.randint(0, len(table) - 1)]
    return res


class HandshakeError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class MessageExpirationError(Exception):
    def __init__(self, expected, got) -> None:
        super().__init__(
            f'Message expried, expected {expected}, got {got}.')


class InvalidMessageError(Exception):
    def __init__(self) -> None:
        super().__init__('Message invalid.')
