import hashlib
import time
import socket
import json
from merkle import MerkleTools
import ecdsa, base58
from threading import Thread
from Crypto.Hash import SHA256
import argparse
import sys
import binascii
import os
from verify import verify
import ctypes
import threading
from requests import get

LIMIT = 100000
HALVE = 10000
CONFIRMATION = 102
CHANGE = 1000
DIFFICULTY = 2
REWARD = 10


def toTuple(listy):
    if isinstance(listy, list): return tuple(map(toTuple, listy))
    if isinstance(listy, dict): return {k: toTuple(v) for k, v in listy.items()}
    return listy


def recvall(s, bufsiz=2048):  # receives ALL data even if it's longer than the buffer size
    recvd = ''
    while True:
        recvd += s.recv(bufsiz).decode()
        if recvd.endswith(':end'):
            data = json.loads(recvd[:-4])
            return data


def enc(d):
    d = json.dumps(d)
    d = d + ':end'
    return d.encode()


def sendall(s, d):
    s.sendall(enc(d))


class Blockchain:
    def __init__(self, **kwargs):
        if 'verb' in kwargs:
            self.verb = kwargs['verb']
        self.change = CHANGE
        self.halve = HALVE
        self.pool = LIMIT
        self.reward = REWARD
        self.diff = DIFFICULTY
        self.confirm = CONFIRMATION
        self.utxo = []
        self.transactions = []
        self.chain = []
        self.nodes = []
        self.temp_spent = []
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect(('127.0.0.1', 9168))
            ip = get('https://api.ipify.org').text
            i = 500
            sendall(self.s, {'type': 'chain', 'start': 0, 'end': i})
            r = recvall(self.s)
            length, chain = r['length'], r['chain']
            v, c = verify(chain).v_chain()

            if length < i:
                if not v:
                    print(json.dumps(chain, indent=4))
                    print('recieved chain was bad, making our own')
                    raise socket.error

            while i <= length:
                if not v:
                    print('recieved chain was bad, making our own')
                    raise socket.error
                i += 500
                if i >= length:
                    break
                sendall(self.s, {'type': 'chain', 'start': i - 500, 'end': i})
                r = recvall(self.s)
                length, chain = r['length'], chain + r['chain']
                v, c = c.v_chain(chain)

            self.chain = chain
            self.utxo = c.utxo
            sendall(self.s, {'type': 'new_node', 'ip': '127.0.0.1', 'port': kwargs['port']})
            r = recvall(self.s)

            for n in r['nodes']:
                self.nodes.append(toTuple(n))

            print('chain accepted')
            self.s.close()
        except WindowsError or socket.error:
            self.genesis()
            print('could not find a node, running our own\n')

    def relay_block(self, block):
        data = {
            'type': 'new_block',
            'block': block
        }
        if self.nodes is not None:
            for i in self.nodes:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect(i)
                except socket.error:
                    self.nodes.remove(i)
                    return False
                sendall(s, data)
                s.close()

    def relay_transactions(self, transaction):
        data = {
            'type': 'transaction',
            'transaction': transaction
        }
        if self.nodes is not None:
            for i in self.nodes:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect(i)
                except socket.error:
                    self.nodes.remove(i)
                    return False
                sendall(s, data)
                s.close()

    def new_node(self, addr):
        if addr not in self.nodes:
            self.nodes.append(addr)
            return True
        else:
            return False

    def v_block(self, block, last_block):
        if last_block['header']['index'] + 1 != block['header']['index']:
            return False
        v_difficulty = True if block['header']['difficulty'] == self.diff else False
        v_reward = True if block['header']['reward'] == self.reward else False and True if block['header']['reward'] == block['header']['coinbase']['out']['amount'] else False
        v_merkle = True if self.merkleRoot(block['transactions']) == block['header']['merkleRoot'] else False
        v_mined = self.v_proof(block)
        v_last = True if self.hash(last_block) == block['header']['previous_hash'] else False
        for i in block['transactions']:
            if not self.verify_transaction(i):
                return False

        if v_difficulty and v_reward and v_merkle and v_mined and v_last:
            return True
        else:
            return False
    def check_reward(self):
        if len(self.chain) == self.halve:
            self.reward = self.reward / 2
            self.halve += HALVE

    def check_difficulty(self):
        if LIMIT - self.pool == self.change:
            self.change += CHANGE
            self.diff += 1
            if self.verb:
                print('Difficulty Changing\n')
        return True

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def genesis(self):
        header = {
            'index': 1,
            'timestamp': time.time(),
            'proof': 100,
            'merkleRoot': 0,
            'coinbase': 0,
            'reward': 10,
            'difficulty': self.diff,
            'previous_hash': 0

        }
        block = {
            'header': header,
            'transactions': 0,
            'hash': 0
        }

        self.chain.append(block)

    def check_chain(self):
        if len(self.chain) >= self.confirm:
            self.confirm += CONFIRMATION
            print('Checking Chain....')
            v, c = verify(self.chain).v_chain()
            if not v:
                print('chain is wrong! Quitting')
                sys.exit()
            else:
                print('chain is right\n')

    def trans_utxo(self, block):
        self.utxo.append(block['header']['coinbase'])
        for b in block['transactions']:
            for o in b['puts']['outputs']:
                self.utxo.append(o)

        for b in block['transactions']:
            for i in b['puts']['inputs']:
                for u in self.utxo:
                    if i['prev_out']['UTXO'] == u['hash']:
                        self.utxo.remove(u)
                        break

    def add_block(self, block):
        if not self.v_block(block, self.last_block):
            return False
        self.temp_spent = []
        self.chain.append(block)
        self.pool = self.pool - self.reward
        self.check_difficulty()
        self.check_reward()
        self.check_chain()
        self.relay_block(block)
        self.trans_utxo(block)
        return True

    def make_block(self):
        header = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'proof': 0,
            'merkleRoot': self.merkleRoot(self.transactions),
            'difficulty': self.diff,
            'coinbase': {
                'out': {
                    'amount': self.reward,
                    'pubKey': None,
                    'rand': binascii.hexlify(os.urandom(4)).decode()
                },
                'hash': None

            },
            'reward': self.reward,
            'previous_hash': self.hash(self.last_block)

        }
        block = {
            'header': header,
            'transactions': self.transactions,
            'hash': None

        }
        self.transactions = []
        return block

    @property
    def last_block(self):
        return self.chain[-1]

    def transaction(self, t):
        if t not in self.transactions:
            v = self.verify_transaction(t)
            if v is True:
                print(f'transaction {t["txid"]} verified\n')
                self.transactions.append(t)
                self.relay_transactions(t)
                for s in t['puts']['inputs']:
                    self.temp_spent.append(s['prev_out']['UTXO'])
                return True
            else:
                print(f'Transaction {t["txid"]} invalid: {v}\n')
            return False

    @staticmethod
    def merkleRoot(transactions):
        m = MerkleTools()
        for i in transactions:
            m.add_leaf(i['txid'])
        m.make_tree()
        return m.get_merkle_root()

    def verify_transaction(self, trans):
        outs = []
        inp = []
        total = 0
        check = 0

        for i in trans['puts']['inputs']:
            if i['prev_out']['UTXO'] in self.temp_spent:
                return 'Duplicate transactions'

        if self.hash(trans['puts']) != trans['txid']:
            return 'Invalid txid'

        for i in trans['puts']['inputs']:
            inp.append(i['prev_out']['UTXO'])

        if not inp:
            return 'No inputs specified'

        for u in self.utxo:
            for p in inp:
                if u['hash'] == p:
                    outs.append(u)
                    pub = ecdsa.VerifyingKey.from_string(base58.b58decode(u['out']['pubKey']), curve=ecdsa.SECP256k1)
                    total += u['out']['amount']

        if not outs:
            return 'Could not find usable outputs; not enough coins'

        for o in trans['puts']['outputs']:
            if self.hash(o['out']) != o['hash']:
                return 'Invalid output hash'
            check += o['out']['amount']

        if check != total:
            return 'Input value does not match output value'

        for i in trans['puts']['inputs']:
            m = json.dumps(i['prev_out']).encode()
            sig = binascii.unhexlify(base58.b58decode(i['sig']))
            if not pub.verify(sig, m):
                return 'Signature is invalid'
        return True

    def value(self, address):
        total = 0
        for u in self.utxo:
            if address in u['out']['pubKey']:
                total += u['out']['amount']
        return total

    def v_proof(self, block):
        guess_hash = self.hash(block['header'])
        if guess_hash.startswith('0' * self.diff):
            return True
        else:
            return False


class Client:
    def __init__(self, bc):
        self.blockchain = bc

    def make_transaction(self, private, amount, recipient):
        private = base58.b58decode(private.encode())
        private = ecdsa.SigningKey.from_string(private, curve=ecdsa.SECP256k1)
        public = base58.b58encode(private.get_verifying_key().to_string()).decode()
        total_inputs_amount = 0
        utxo = []
        transaction = {
            'txid': None,
            'puts': {
                'inputs': [],
                'outputs': []
            }
        }

        for u in self.blockchain.utxo:
            if u['hash'] in self.blockchain.temp_spent:
                continue
            if u['out']['pubKey'] == public:
                total_inputs_amount += u['out']['amount']
                utxo.append(u)
                if total_inputs_amount >= amount:
                    out = {
                        'out': {
                            'amount': amount,
                            'pubKey': recipient,
                            'rand': binascii.hexlify(os.urandom(4)).decode()
                        },
                        'hash': None
                    }
                    out['hash'] = self.blockchain.hash(out['out'])
                    transaction['puts']['outputs'].append(out)
                    if total_inputs_amount > amount:
                        out = {
                            'out': {
                                'amount': total_inputs_amount - amount,
                                'pubKey': recipient,
                                'rand': binascii.hexlify(os.urandom(4)).decode()
                            },
                            'hash': None
                        }
                        out['hash'] = self.blockchain.hash(out['out'])
                        transaction['puts']['outputs'].append(out)
                    break

        for u in utxo:
            input = {
                'prev_out': {
                    'UTXO': u['hash'],
                    'rand': binascii.hexlify(os.urandom(4)).decode()
                },
                'sig': None
            }
            input['sig'] = base58.b58encode(binascii.hexlify(private.sign(json.dumps(input['prev_out']).encode()))).decode()
            transaction['puts']['inputs'].append(input)
        transaction['txid'] = self.blockchain.hash(transaction['puts'])
        return self.blockchain.transaction(transaction)


    """def make_transaction(self, private, amount, recipient):
        private = base58.b58decode(private.encode())
        private = ecdsa.SigningKey.from_string(private, curve=ecdsa.SECP256k1)
        public = base58.b58encode(private.get_verifying_key().to_string()).decode()
        b = []
        outs = []
        i = 0

        using = []
        total = 0
        for u in self.blockchain.utxo:
            if u['out']['pubKey'] == public:
                outs.append(u)

        for a in outs:
            b.append(a['out']['amount'] - amount)

        while i < amount:
            m = outs[b.index(max(b))]
            using.append(m)
            b.remove(max(b))
            outs.remove(outs[b.index(max(b))])
            i += m['out']['amount']

        # if m['left'] < 0:
        #    using.append(outs[b.index(min(b))])

        blank_trans = {
            'txid': None,
            'puts': {
                'inputs': [],
                'outputs': []
            }
        }

        for i in using:
            total += i['out']['amount']
            inp = {
                'prev_out': {
                    'UTXO': i['hash'],
                    'rand': binascii.hexlify(os.urandom(4)).decode()
                },
                'sig': None
            }
            blank_trans['puts']['inputs'].append(inp)

        d = {
            'out': {
                'amount': amount,
                'pubKey': recipient,
                'rand': binascii.hexlify(os.urandom(4)).decode()
            },
            'hash': None

        }
        d['hash'] = self.blockchain.hash(d['out'])

        blank_trans['puts']['outputs'].append(d)
        if total - amount != 0:
            m = {
                'out': {
                    'amount': total - amount,
                    'pubKey': public,
                    'rand': binascii.hexlify(os.urandom(4)).decode()
                },
                'hash': None

            }
            m['hash'] = self.blockchain.hash(m['out'])
            blank_trans['puts']['outputs'].append(m)

        for s in blank_trans['puts']['inputs']:
            s['sig'] = base58.b58encode(binascii.hexlify(private.sign(json.dumps(s['prev_out']).encode()))).decode()

        blank_trans['txid'] = self.blockchain.hash(blank_trans['puts'])

        return self.blockchain.transaction(blank_trans)"""

    def mine(self, address):
        print('Mining started! press q to stop, may take a couple tries.\n')
        while True:
            block = self.blockchain.make_block()
            block['header']['coinbase']['out']['pubKey'] = address
            block['header']['coinbase']['hash'] = self.blockchain.hash(block['header']['coinbase']['out'])
            while not self.blockchain.hash(block['header']).startswith('0' * self.blockchain.diff):
                if block['header']['index'] <= self.blockchain.chain[-1]['header']['index']:
                    continue
                block['header']['proof'] += 1
            if self.blockchain.add_block(block):
                print(f'block {block["header"]["index"]} added\n')
            else:
                print(f'block {block["header"]["index"]} rejected\n')

    @staticmethod
    def generate(): # generate key pair in base64
        private = SHA256.new(os.urandom(32)).digest()
        sk = ecdsa.SigningKey.from_string(private, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        public = vk.to_string()
        return base58.b58encode(private).decode(), base58.b58encode(public).decode()


class server(Thread):
    def __init__(self, blockchain, port, **kwargs):
        super(server, self).__init__()
        if 'verb' in kwargs:
            self.verb = kwargs['verb']
        self.log = []
        self.port = port
        self.blockchain = blockchain
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        self.s.bind(('0.0.0.0', self.port))
        self.s.listen(100)
        try:
            while True:
                self.accept()
        finally:
            pass

    def logging(self, input):
        self.log.append(input)

    def accept(self):
        client, addr = self.s.accept()
        addr = str(addr)
        self.logging('Client %s has connected\n' % addr)
        Thread(target=self.receive, args=(client, addr,)).start()

    def receive(self, client, addr):
        while True:
            data = recvall(client)
            if not data:
                client.close()
                self.logging('client %s has disconnected\n' % addr)
                sys.exit()
            if data['type'] == 'mine':
                self.test(data, client, addr)
                break
            self.test(data, client, addr)

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

    @staticmethod
    def decode(data):
        try:
            data = json.loads(data.decode())
            return data
        except:
            return False

    def test(self, data, client, addr):
        type = data['type']
        if type == 'transaction':
            self.logging('Client %s has requested a transaction \n' % addr)
            self.blockchain.transaction(data['transaction'])
            return None
        elif type == 'chain':  # to get the full chain set end as -1
            s = data['start']
            e = data['end']
            if e > len(self.blockchain.chain):
                e = len(self.blockchain.chain)
            self.logging('Client %s requested a copy of the blockchain\n' % addr)
            sendall(client, {
                'chain': self.blockchain.chain[s:e],
                'length': len(self.blockchain.chain)
            })
            return None

        elif type == 'new_node':
            address = (data['ip'], data['port'])
            nodes = self.blockchain.nodes.copy()
            this = ('127.0.0.1', self.port)
            nodes.append(this)
            if self.blockchain.new_node(address):
                sendall(client, {
                    'nodes': nodes,
                })
                self.logging('a new node at %s, has connected\n' % addr)
                return None
        elif type == 'new_block':
            if data['block'] not in self.blockchain.chain:
                self.blockchain.add_block(data['block'])
            return None
        elif type == 'get_utxo':
            sendall(client, {
                'type': 'utxo',
                'utxo': self.blockchain.utxo
            })
            return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This is a node for blockcoin')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show more output')
    parser.add_argument('-s', '--start', action='store_true', help='Start the node')
    parser.add_argument('-p', '--port', action='store', help='the port for the node to listen on (default: 9168)')
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    verb = False
    if args.port:
        port = int(args.port)
    else:
        port = 9168
    if args.verbose:
        verb = True
    Blocks = Blockchain(verb=verb, port=port)
    if args.start:
        server(Blocks, port, verb=True)
