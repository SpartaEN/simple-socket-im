from sqlite3.dbapi2 import Error
from .socket_client import Client
from .socket_server import Server, ClientConnection
from .aes import AESCipher
from utils.helpers import HandshakeError, MessageExpirationError, InvalidMessageError, keep_alive
from time import sleep
from os.path import exists
import ntpath


class Chat():
    def __init__(self, addr, port, is_server, secret=None, username=None, in_msg_cb=lambda x: None, in_noti_cb=lambda x: None, change_input_lck=lambda x: None, change_title=lambda x: None, group_chat=False, ssl_cert_location=None) -> None:
        super().__init__()
        self.__is_group_chat = group_chat
        self.__incoming_msg_handler = in_msg_cb
        self.__incoming_notification_handler = in_noti_cb
        self.__change_text_field_status = change_input_lck
        self.__change_title = change_title
        self.__username = username
        self.__secret = secret
        self.__peername = None
        self.__group_chat_cookie = None
        if secret is not None and not group_chat:
            self.__aes = AESCipher(secret)
            self.__encrypt = True
        else:
            self.__aes = AESCipher('')
            self.__encrypt = False
        try:
            if is_server:
                self.server = Server(addr, port)
                self.server.add_conn_handler(self.__handle_new_conn)
                self.server.set_challenge_handler(
                    self.__aes.server_challenge_verify)
                # self.server.add_exception_cb(self.exception_callback)
                self.server.start()
            else:
                self.peer = Client(addr, port, group_chat, ssl_cert_location)
                self.peer.add_exception_cb(self.exception_callback)
                self.peer.add_msg_callback(self.__msg_callback)
                self.peer.set_challenge_handler(
                    self.__aes.client_challenge_construct)
                self.__incoming_notification_handler(
                    f'Connected to {addr}:{port}')
                self.peer.start()
                sleep(1)
                if group_chat:
                    self.peer.send_msg(b'\x21\x01' + len(self.__username).to_bytes(1, 'little') + self.__username.encode(
                        'utf-8') + len(self.__secret).to_bytes(1, 'little') + self.__secret.encode('utf-8'))
                else:
                    if self.__username != None:
                        payload = b'\x00' + \
                            len(self.__username).to_bytes(1, 'little') + \
                            self.__username.encode('utf-8')
                        if self.__encrypt:
                            self.peer.send_msg(
                                self.__aes.encrypt(payload), True)
                        else:
                            self.peer.send_msg(payload)
                    keep_alive(self.peer, self.exception_callback)
                self.__change_text_field_status(True)
        except HandshakeError:
            self.__incoming_notification_handler(
                'Failed to connect to peer: Handshake error!')
            self.__change_text_field_status(False)

    def __handle_new_conn(self, conn, addr):
        try:
            self.peer = ClientConnection(conn)
            self.peer.add_msg_callback(self.__msg_callback)
            self.__incoming_notification_handler(
                f'Accepted new connection from {addr[0]}:{addr[1]}')
            self.peer.start()
            sleep(1)
            if self.__username != None:
                payload = b'\x00' + \
                    len(self.__username).to_bytes(1, 'little') + \
                    self.__username.encode('utf-8')
                if self.__encrypt:
                    self.peer.send_msg(self.__aes.encrypt(payload), True)
                else:
                    self.peer.send_msg(payload)
            keep_alive(self.peer, self.exception_callback)
            self.__change_text_field_status(True)
        except HandshakeError:
            self.__incoming_notification_handler(
                'Failed to connect to peer: Handshake error!')
            self.__change_text_field_status(False)

    def __msg_callback(self, msg: bytes, encryption) -> None:
        try:
            if self.__is_group_chat:
                op = msg[0]
                if op == 0x21:
                    phase = msg[1]
                    status = msg[2]
                    if phase == 0x02 and status == 0x01:
                        # Success
                        self.__incoming_notification_handler('Login success!')
                        self.__group_chat_cookie = msg[3:]
                    else:
                        self.__incoming_notification_handler(
                            f'Failed to login {msg[3:].decode("utf-8")}')
                        self.__change_text_field_status(False)
                elif op == 0x23:
                    username_len = msg[1]
                    username = msg[2:2+username_len].decode('utf-8')
                    message_len = int.from_bytes(
                        msg[2+username_len:2+username_len+4], 'little')
                    message = msg[2+username_len +
                                  4:2+username_len+4+message_len].decode('utf-8')
                    self.__incoming_msg_handler(message, username)
                elif op == 0x24:
                    message_len = int.from_bytes(msg[1:5], 'little')
                    message = msg[5:5+message_len].decode('utf-8')
                    self.__incoming_notification_handler(message)
            else:
                if encryption:
                    msg = self.__aes.decrypt(msg)
                op = msg[0]
                if op == 0:
                    peername_length = msg[1]
                    self.__peername = msg[2:2+peername_length].decode('utf-8')
                    self.__change_title(self.__peername)
                elif op == 1:
                    if self.__peername != None:
                        msg_len = int.from_bytes(msg[1:5], 'little')
                        self.__incoming_msg_handler(
                            msg[5:5+msg_len].decode('utf-8'), self.__peername)
                    else:
                        msg_len = int.from_bytes(msg[1:5], 'little')
                        self.__incoming_msg_handler(
                            msg[5:5+msg_len].decode('utf-8'))
                elif op == 5:
                    file_name_len = msg[1]
                    file_name = msg[2:2+file_name_len].decode('utf-8')
                    file_len = int.from_bytes(
                        msg[2+file_name_len: 2+file_name_len+4], 'little')
                    file_data = msg[2+file_name_len+4:]
                    file_name = ntpath.basename(file_name)
                    if len(file_data) == file_len:
                        with open('files/' + file_name, 'wb') as f:
                            f.write(file_data)
                        self.__incoming_notification_handler(
                            f'Received file {file_name}')
                    else:
                        self.__incoming_notification_handler(
                            f'File {file_name} seems corrupted.')
                elif op == 6:
                    self.__incoming_notification_handler(
                        f'Peer ended the chat.')
                    self.peer.socket.close()
        # Just replay attack prevention
        except MessageExpirationError:
            pass
        except InvalidMessageError:
            pass

    def send_file(self, file_name: str):
        if exists(file_name):
            self.__incoming_notification_handler(f'Sending file {file_name}.')
            with open(file_name, 'rb') as f:
                contents = f.read()
                file_name = ntpath.basename(file_name)
                payload = b'\x05' + len(file_name).to_bytes(1, 'little') + file_name.encode(
                    'utf-8') + len(contents).to_bytes(4, 'little') + contents
                print(f'File packed, length: {len(contents)}')
                if self.__encrypt:
                    self.peer.send_msg(self.__aes.encrypt(payload), True)
                else:
                    self.peer.send_msg(payload)
                self.__incoming_notification_handler(f'File {file_name} sent.')
        else:
            self.__incoming_notification_handler(
                f'File {file_name} not exists.')

    def end_chat(self):
        if not self.__is_group_chat:
            self.peer.send_msg(b'\x06')
        else:
            self.peer.send_msg(
                b'\x06'+len(self.__group_chat_cookie).to_bytes(1, 'little') + self.__group_chat_cookie)
        self.__change_text_field_status(False)
        sleep(1)
        try:
            self.peer.socket.close()
        except:
            pass

    def process_input(self, msg: str):
        msg = msg.encode('utf-8')
        if self.__is_group_chat:
            payload = b'\x22' + len(self.__group_chat_cookie).to_bytes(
                1, 'little') + self.__group_chat_cookie + len(msg).to_bytes(4, 'little') + msg
        else:
            payload = b'\x01' + len(msg).to_bytes(4, 'little') + msg
        if self.__encrypt:
            self.peer.send_msg(self.__aes.encrypt(payload), True)
        else:
            self.peer.send_msg(payload)

    def get_online_users(self):
        self.peer.send_msg(
            b'\x25'+len(self.__group_chat_cookie).to_bytes(1, 'little')+self.__group_chat_cookie)

    def exception_callback(self, e):
        print(e)
        self.__incoming_notification_handler(f'Conntion terminated: {e}')
        self.__change_text_field_status(False)
