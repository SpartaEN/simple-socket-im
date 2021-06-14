from tkinter import *
from datetime import datetime
import tkinter
from tkinter.messagebox import showerror
from utils.chat import Chat


class ChatGUI(tkinter.Tk):
    def __init__(self, addr, port, is_server=False, secret=None, username=None) -> None:
        super().__init__()
        self.username = username
        self.wm_title('P2P Chat')
        self.messages = Text(self)
        self.messages.tag_configure('user-self', foreground='red')
        self.messages.tag_configure('user-peer', foreground='green')
        self.messages.tag_configure('system', foreground='blue')
        self.messages.see('end')
        self.messages.pack()
        self.input_user = StringVar()
        self.input_field = Entry(self, text=self.input_user)
        self.input_field.pack(side=BOTTOM, fill=X)
        # 300 x 300
        self.frame = Frame(self)
        self.input_field.bind("<Return>", self.enter_pressed)
        self.frame.pack()
        self.input_field.configure(state='disable')
        self.messages.insert(
            INSERT, f'Welcome to P2P Chat. \nUse /sendfile <filename> to send files.\n', 'system')
        self.messages.configure(state='disable')
        try:
            self.chat = Chat(addr, port, is_server, secret, username, self.incoming_msg,
                             self.incoming_notification, self.change_text_field_status, self.set_title)
        except Exception as e:
            showerror(title='Oops', message=e)
            self.destroy()

    def enter_pressed(self, event):
        input_get = self.input_field.get()
        self.messages.configure(state='normal')
        self.input_user.set('')
        self.input_field.delete(0, END)
        if input_get[0:10] == '/sendfile ':
            self.chat.send_file(input_get[10:])
            return 'break'
        self.chat.process_input(input_get)
        date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.messages.insert(INSERT, f'[{date}] ')
        if self.username:
            self.messages.insert(
                INSERT, f'YOU({self.username}): ', 'user-self')
        else:
            self.messages.insert(INSERT, f'YOU: ', 'user-self')
        self.messages.insert(INSERT, f'{input_get}\n')
        self.messages.configure(state='disable')
        return 'break'

    def incoming_msg(self, msg, peer_name='PEER'):
        date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.messages.configure(state='normal')
        self.messages.insert(INSERT, f'[{date}] ')
        self.messages.insert(INSERT, f'{peer_name}: ', 'user-peer')
        self.messages.insert(INSERT, f'{msg}\n')
        self.messages.configure(state='disable')

    def incoming_notification(self, msg):
        date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.messages.configure(state='normal')
        self.messages.insert(INSERT, f'[{date}] {msg}\n', 'system')
        self.messages.configure(state='disable')

    def set_title(self, peer_name):
        self.wm_title(f'P2P Chat - {peer_name}')

    def change_text_field_status(self, status):
        if status:
            self.input_field.configure(state='normal')
        else:
            self.input_field.configure(state='disable')

    def mainloop(self):
        super().mainloop()
