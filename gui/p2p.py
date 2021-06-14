from gui.chat import ChatGUI
from tkinter import *
from tkinter.messagebox import showerror
from utils.helpers import gen_secret


class P2P(Tk):
    def __init__(self) -> None:
        super().__init__()
        self.wm_title('P2P Chat')
        self.geometry('240x150')

        self.addr_label = Label(self, text="Server Address")
        self.addr_label.grid(row=0, column=0)
        self.address = StringVar()
        self.address.set('0.0.0.0')
        self.addr_entry = Entry(self, textvariable=self.address)
        self.addr_entry.grid(row=0, column=1)

        self.port_label = Label(self, text="Server Port")
        self.port_label.grid(row=1, column=0)
        self.port = IntVar()
        self.port.set(5000)
        self.port_entry = Entry(self, textvariable=self.port)
        self.port_entry.grid(row=1, column=1)

        self.encryption = BooleanVar()
        self.encryption.set(True)
        self.encryption_check = Checkbutton(
            text='Use encryption', variable=self.encryption, command=self.update_encryption_entries)
        self.encryption_check.grid(row=2, column=0)

        self.secret_label = Label(self, text="Encrypion Key")
        self.secret_label.grid(row=3, column=0)
        self.secret = StringVar()
        self.secret.set(gen_secret())
        self.secret_entry = Entry(self, textvariable=self.secret)
        self.secret_entry.grid(row=3, column=1)

        self.username_label = Label(self, text="Username")
        self.username_label.grid(row=4, column=0)
        self.username = StringVar()
        self.username_entry = Entry(self, textvariable=self.username)
        self.username_entry.grid(row=4, column=1)

        self.start_btn = Button(self, text="Start Server",
                                command=self.start_server)
        self.start_btn.grid(row=5, column=0)
        self.start_btn = Button(self, text="Start Client",
                                command=self.start_client)
        self.start_btn.grid(row=5, column=1)

    def update_encryption_entries(self):
        if self.encryption.get():
            self.secret_entry.configure(state='normal')
        else:
            self.secret_entry.configure(state='disable')

    def start_server(self):
        username = self.username.get()
        if username == '':
            username = None
        if self.encryption.get():
            secret = self.secret.get()
        else:
            secret = None
        self.chat = ChatGUI(self.address.get(),
                            self.port.get(), True, secret, username)
        self.destroy()
        self.chat.mainloop()

    def start_client(self):
        username = self.username.get()
        if username == '':
            username = None
        if self.encryption.get():
            secret = self.secret.get()
        else:
            secret = None
        self.chat = ChatGUI(self.address.get(),
                            self.port.get(), False, secret, username)
        self.destroy()
        self.chat.mainloop()
