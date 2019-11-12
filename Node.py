import kivy
kivy.require('1.10.1')
from kivy.app import App
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.core.window import Window
from kivy.properties import StringProperty
import weakref
from kivy.uix.label import Label
import blocks
import ecdsa
import base64, base58
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography
import os
import json
import threading
import ctypes
import sys
from kivy.clock import Clock


class startPop(Popup):
    def __init__(self, node):
        super(startPop, self).__init__()
        self.node = node

    def start(self):
        global Blocks, server, Client
        self.ids.port.focus = False
        self.dismiss()
        port = int(self.ids.port.text)
        Blocks = blocks.Blockchain(verb=False, port=port)
        Client = blocks.Client(Blocks)
        # server = threading.Thread(target=blocks.server.__init__, args=(Blocks, port,))
        server = blocks.server(Blocks, port, verb=False)
        server.start()
        self.node.start()


class kpop(Popup):

    def importKeys(self, pw):
        global privateObj, publicObj, private, public
        with open('private.key', 'rb') as f:
            key = f.read()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=b'not random', iterations=100,
                         backend=default_backend())
        pw = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
        f = Fernet(pw)
        try:
            key = f.decrypt(key)
        except cryptography.fernet.InvalidToken:
            self.open()
            self.ids.pwLabel.text = 'incorrect password, retry'
            self.ids.pw2.text = ''
            return

        private = key
        key = base58.b58decode(key)
        privateObj = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
        publicObj = privateObj.get_verifying_key()
        public = base58.b58encode(publicObj.to_string()).decode()
        self.ids.pw2.focus = False
        self.dismiss()


class Node(TabbedPanel):

    class Save(Button):
        class Pop(Popup):
            def save(self, pw):
                with open('private.key', 'wb') as priv:
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=b'not random', iterations=100,
                                     backend=default_backend())
                    key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
                    f = Fernet(key)
                    priv.write(f.encrypt(private.encode()))

        def popup(self):
            self.Pop().open()

    def transaction(self, private, amount, recipient):
        return Client.make_transaction(private, amount, recipient)

    def check_value_private(self, private):
        public = base58.b58encode(ecdsa.SigningKey.from_string(base58.b58decode(private), curve=ecdsa.SECP256k1).get_verifying_key().to_string())
        print(public)
        return str(Blocks.value(public.decode()))

    def gen(self):
        global public, private
        private, public = Client.generate()

        self.ids.g_buttons.remove_widget(self.ids.gen)
        self.ids.g_buttons.add_widget(self.Save())
        self.ids.key.text = f'public: {public}\n\nprivate:\n {private}'

    def mine(self, address):
        global mining
        self.ids.mine.clear_widgets()
        self.stop_btn = Button(id='stop_btn', text='stop')
        self.stop_btn.bind(on_release=self.stop_mining)
        self.ids.mine.add_widget(self.stop_btn)
        self.ids.mine_text.text += 'Mining started\n'
        mining = thread(Client.mine, address)
        mining.start()

    def stop_mining(self, instance):
        global mining
        self.ids.mine_text.text += 'Mining ended\n'
        self.ids.mine.remove_widget(self.stop_btn)
        text = TextInput(id='address', hint_text='address', size_hint_x=0.8, multiline=False)
        btn = Button(id='start_mining', text='start!', size_hint_x=0.2)
        mine = lambda x: self.mine(text.text)
        btn.bind(on_release=mine)
        self.ids.mine.add_widget(text)
        self.ids.mine.add_widget(btn)
        if public is not None:
            text.text = public

        mining.raise_exception()
        mining.join()

    def load(self, last):
        i = 10
        label = None
        if last - 100 < 0:
            chain = self.chain[:last]
        else:
            chain = self.chain[last - 100: last]
        chain.reverse()
        for c in chain:
            if i == 10:
                label = Label(size_hint=(None, None), text='')
                label.index = c['header']['index'] - 10
                self.ids.chain.add_widget(label, 1)
                i = 0
            label.text += json.dumps(c, indent=4) + '\n'
            label._label.refresh()
            label.size = label._label.texture.size
            i += 1
        if last - 100 < 0:
            self.ids.chain.remove_widget(self.ids.load)

    def start(self):
        global private, public
        if public is not None:
            print(public)
            self.ids.address.text = public
            self.ids.private.text = private

        self.chain = []
        Clock.schedule_interval(self.update, 0.1)

    def update(self, dt):
        for c in Blocks.chain[len(self.chain):]:
            if len(self.chain) == 0:
                self.label = Label(size_hint=(None, None), text='')
                self.label.index = c['header']['index'] - 1
                self.ids.chain.add_widget(self.label, 1)
            if len(self.chain) == 10:
                self.ids.load.opacity = 1.0
                self.ids.load.bind(on_press=lambda x: self.load(self.ids.chain.children[1].index))
            if len(self.chain) % 10 == 0:
                self.label = Label(size_hint=(None, None), text='')
                self.label.index = c['header']['index'] - 1
                self.ids.chain.add_widget(self.label, -1)
                if len(self.ids.chain.children) == 11:
                    self.ids.chain.remove_widget(self.ids.chain.children[1])

            if c not in self.chain:
                self.chain.append(c)
                # self.ids.chain.data.append({'text': json.dumps(c, indent=4)})
                self.label.text = json.dumps(c, indent=4) + '\n' + self.label.text
                self.label._label.refresh()
                self.label.size = self.label._label.texture.size


class NodeApp(App):

    def on_start(self):
        startPop(self.node).open()
        if os.path.isfile('private.key'):
            kpop().open()

    def build(self):
        self.node = Node()
        return self.node

    def on_stop(self):
        server.raise_exception()
        quit()



class thread(threading.Thread):
    def __init__(self, func, param):
        threading.Thread.__init__(self)
        self.func = func
        self.param = param

    def run(self):
        try:
            self.func(self.param)
        finally:
            print('ended')

    def get_id(self):

        # returns id of the respective thread
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def raise_exception(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id,
                                                         ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)


if __name__ == '__main__':
    private = None
    public = None
    privateObj = None
    publicObj = None
    Blocks = None
    Client = None
    mining = None
    server = None
    NodeApp().run()
