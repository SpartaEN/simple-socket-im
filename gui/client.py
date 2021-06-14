from tkinter import messagebox
from gui.chat import ChatGUI
from tkinter import *
from tkinter.messagebox import showerror


class Client(Tk):
    def __init__(self) -> None:
        super().__init__()
        self.wm_title('Simple Chat')
        self.geometry('240x150')

        self.addr_label = Label(self, text="Server Address")
        self.addr_label.grid(row=0, column=0)
        self.address = StringVar()
        self.address.set('127.0.0.1')
        self.addr_entry = Entry(self, textvariable=self.address)
        self.addr_entry.grid(row=0, column=1)

        self.port_label = Label(self, text="Server Port")
        self.port_label.grid(row=1, column=0)
        self.port = IntVar()
        self.port.set(5000)
        self.port_entry = Entry(self, textvariable=self.port)
        self.port_entry.grid(row=1, column=1)

        self.username_label = Label(self, text="Username")
        self.username_label.grid(row=2, column=0)
        self.username = StringVar()
        self.username_entry = Entry(self, textvariable=self.username)
        self.username_entry.grid(row=2, column=1)

        self.password_label = Label(self, text="Password")
        self.password_label.grid(row=3, column=0)
        self.password = StringVar()
        self.password_entry = Entry(self, textvariable=self.password, show='*')
        self.password_entry.grid(row=3, column=1)

        self.cert_label = Label(self, text="SSL Cert")
        self.cert_label.grid(row=4, column=0)
        self.cert = StringVar()
        self.cert.set('certs/cert.pem')
        self.cert_entry = Entry(self, textvariable=self.cert)
        self.cert_entry.grid(row=4, column=1)

        self.start_btn = Button(self, text="Connect",
                                command=self.connect)
        self.start_btn.grid(row=5, column=0)

        self.start_btn = Button(self, text="Reset",
                                command=self.reset)
        self.start_btn.grid(row=5, column=1)

    def reset(self):
        self.username.set('')
        self.password.set('')

    def connect(self):
        username = self.username.get()
        password = self.password.get()
        cert = self.cert.get()
        if username == '' or password == '':
            messagebox.showwarning(
                'Warning', 'Username or password can\'t be empty')
        self.chat = ChatGUI(self.address.get(), self.port.get(),
                            False, password, username, True, cert)
        self.destroy()
        self.chat.mainloop()
