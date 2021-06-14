from utils.socket_server import Server, ClientConnection
from utils.helpers import gen_secret
from time import sleep
from models.users import User

addr = '127.0.0.1'
port = 5000
# SSL Must be enabled
use_ssl = True
ssl_cert_location = 'certs/cert.pem'
ssl_cert_key_location = 'certs/key_nopass.pem'

session = {}
clients = []


def get_assiciated_user(session_id):
    try:
        s = session[session_id]
        if s['status'] == False:
            return False
        else:
            return s['username']
    except KeyError:
        return False


def broadcast_msg(msg, src, src_username):
    payload = b'\x23' + len(src_username).to_bytes(1, 'little') + \
        src_username + len(msg).to_bytes(4, 'little') + msg
    for conn in clients:
        session_id = conn.get_identifier()
        username = get_assiciated_user(session_id)
        try:
            if session_id != src and username != False:
                conn.send_msg(payload)
        except:
            kick_user(session_id, conn, username)


def broadcast_msg_system(msg):
    payload = b'\x24' + len(msg).to_bytes(4, 'little') + msg.encode('utf-8')
    for conn in clients:
        session_id = conn.get_identifier()
        username = get_assiciated_user(session_id)
        try:
            if username != False:
                conn.send_msg(payload)
        except:
            kick_user(session_id, conn, username)


def msg_system(msg, session_id):
    payload = b'\x24' + len(msg).to_bytes(4, 'little') + msg.encode('utf-8')
    for conn in clients:
        try:
            username = get_assiciated_user(session_id)
            if conn.get_identifier() == session_id:
                conn.send_msg(payload)
        except:
            kick_user(session_id, conn, username)


def kick_user(session_id, conn, user):
    try:
        print(f'Dropping user {user.decode("utf-8")} for session {session_id}')
        session[session_id]['status'] = False
        conn.socket.close()
    except:
        pass


def get_online_users():
    users = []
    for sess_id in list(session.keys()):
        username = get_assiciated_user(sess_id)
        if username != False:
            users.append(username.decode('utf-8'))
    return users


def logout(session_id):
    username = get_assiciated_user(session_id)
    if username != False:
        session[session_id]['status'] = False
        print(f'User {username.decode("utf-8")} logged out.')
        try:
            for conn in clients:
                if conn.get_identifier() == session_id:
                    conn.socket.close()
        except:
            pass


def server_exception_cb(e):
    print(f'Failed to establish connection: {e}')


def message_cb(msg, encrypt):
    op = msg[0]
    if op == 0x22:
        session_len = msg[1]
        session_id = msg[2:2+session_len]
        message_len = int.from_bytes(
            msg[2+session_len:6+session_len], 'little')
        message = msg[6+session_len:6+session_len+message_len]
        user = get_assiciated_user(session_id.decode('utf-8'))
        if user != False:
            print(f'[CHAT] {user.decode("utf-8")}: {message.decode("utf-8")}')
            broadcast_msg(message, session_id.decode('utf-8'), user)
    elif op == 0x25:
        session_len = msg[1]
        session_id = msg[2:2+session_len].decode('utf-8')
        msg_system('Online users: '+', '.join(get_online_users()), session_id)
    elif op == 0x06:
        session_len = msg[1]
        session_id = msg[2:2+session_len].decode('utf-8')
        user = get_assiciated_user(session_id)
        if user != False:
            broadcast_msg_system(f'User {user.decode("utf-8")} left the chat.')
            logout(session_id)


def on_new_connection(conn, addr):
    # Authication
    print(f'Accepted {addr[0]}:{addr[1]}')
    userinfo = conn.recv(1024)[5:]
    # Parse userinfo manually
    op = userinfo[0]
    phase = userinfo[1]
    if op == 0x21 and phase == 1:
        username_len = userinfo[2]
        username = userinfo[3:3+username_len]
        password_len = userinfo[4+username_len]
        password = userinfo[4+username_len:4+username_len+password_len]
        user = User.get_user(username.decode('utf-8'))
        if user != None and user.check_user(password):
            # Add user to
            session_id = gen_secret(16)
            session[session_id] = {
                'username': username,
                'status': True
            }
            client_conn = ClientConnection(conn, session_id)
            client_conn.add_exception_cb(server_exception_cb)
            client_conn.add_msg_callback(message_cb)
            clients.append(client_conn)
            client_conn.start()
            print(
                f'User {username.decode("utf-8")} logged in successfully from {addr[0]}:{addr[1]}')
            broadcast_msg_system(
                f'User {username.decode("utf-8")} joined the chat.')
            client_conn.send_msg(b'\x21\x02\x01'+session_id.encode('utf-8'))
        else:
            print(
                f'Failed login attempt from {addr[0]}:{addr[1]}, user {username.decode("utf-8")}.')
            conn.send(
                b'\x01\x1f\x00\x00\x00\x21\x02\x00Invalid username or password')
            conn.close()
    else:
        conn.send(b'\x01\x12\x00\x00\x00\x21\x02\x00MalformedPacket')
        conn.close()


server = Server(addr, port, 0, use_ssl,
                ssl_cert_location, ssl_cert_key_location)
server.add_conn_handler(on_new_connection)
server.add_exception_cb(server_exception_cb)
server.start()

try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    exit(0)
