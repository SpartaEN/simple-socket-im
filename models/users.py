import sqlite3
import bcrypt

conn = sqlite3.connect('user.db', check_same_thread=False)

cursor = conn.cursor()


class User():
    def __init__(self, uid, username, password) -> None:
        self.__uid = uid
        self.__username = username
        self.__password = password
        pass

    @staticmethod
    def initialize():
        sql = '''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(64) UNIQUE,
            password VARCHAR(64)
        )
        '''
        cursor.execute(sql)
        username = 'cisco'
        password = bcrypt.hashpw(b'cisco', bcrypt.gensalt())
        try:
            cursor.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)', [username, password])
        except sqlite3.IntegrityError:
            pass
        conn.commit()

    @staticmethod
    def get_user(username):
        cursor.execute('SELECT * FROM users WHERE username = ?', [username])
        user = cursor.fetchone()
        if user == None:
            return None
        return User(user[0], user[1], user[2])

    @staticmethod
    def create(username: str, password: str):
        try:
            hashed_password = bcrypt.hashpw(
                password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed_password])
            conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)

    def get_username(self):
        return self.__username

    def get_uid(self):
        return self.__uid

    def check_user(self, password: bytes):
        return bcrypt.checkpw(password, self.__password)
