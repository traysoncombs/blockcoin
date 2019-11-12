import ecdsa
import base58
import binascii
import merkle
import json
import hashlib
LIMIT = 100000
HALVE = 10000
CHANGE = 1000
DIFFICULTY = 2
REWARD = 10


class verify:
    def __init__(self, chain):
        self.chain = chain
        self.pool = LIMIT
        self.difficulty = DIFFICULTY
        self.reward = REWARD
        self.utxo = []
        self.change = CHANGE
        self.last_block = 0
        self.halve = HALVE

    def v_chain(self, chain=''):
        if chain:
            self.chain += chain
        for c in self.chain[1:]:
            if self.v_block(c, self.chain[self.last_block]):
                self.pool -= self.reward
                self.check_difficulty()
                self.check_reward()
                self.last_block += 1
            else:
                print('chain is wrong')
                return False, None
        return True, self

    def check_reward(self):
        if self.last_block + 2 == self.halve:
            self.reward = self.reward / 2
            self.halve += HALVE

    def check_difficulty(self):
        if LIMIT - self.pool == self.change:
            self.change += CHANGE
            self.difficulty += 1
        return True

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def merkleRoot(transactions):
        m = merkle.MerkleTools()
        for i in transactions:
            m.add_leaf(i['txid'])
        m.make_tree()
        return m.get_merkle_root()

    def v_block(self, block, last_block):
        spent = []
        if last_block['header']['index'] + 1 != block['header']['index']:
            print('bad last block')
            return False
        for t in block['transactions']:
            for i in t['puts']['inputs']:
                if i['prev_out']['UTXO'] in spent:
                    return False
                spent.append(i['prev_out']['UTXO'])

        v_difficulty = True if block['header']['difficulty'] == self.difficulty else False
        v_reward = True if block['header']['reward'] == self.reward else False
        v_merkle = True if self.merkleRoot(block['transactions']) == block['header']['merkleRoot'] else False
        v_mined = self.v_proof(block)
        v_last = True if self.hash(last_block) == block['header']['previous_hash'] else False
        for i in block['transactions']:
            if not self.v_transaction(i):
                print("bad transaction")
                return False

        if v_difficulty and v_reward and v_merkle and v_mined and v_last:
            self.trans_utxo(block)
            return True
        else:
            print(v_difficulty, v_reward, v_merkle, v_mined, v_last)
            return False

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

    def v_proof(self, block):
        guess_hash = self.hash(block['header'])
        if guess_hash.startswith('0' * self.difficulty):
            return True
        else:
            print("bad mining")
            return False

    def v_transaction(self, transaction):
        outs = []
        inp = []
        total = 0
        check = 0

        if self.hash(transaction['puts']) != transaction['txid']:
            print('txid')
            return False

        for i in transaction['puts']['inputs']:
            inp.append(i['prev_out']['UTXO'])

        if not inp:
            print('UTXO')
            return False

        for u in self.utxo:
            for p in inp:
                if u['hash'] == p:
                    outs.append(u)
                    pub = ecdsa.VerifyingKey.from_string(base58.b58decode(u['out']['pubKey']), curve=ecdsa.SECP256k1)
                    total += u['out']['amount']

        if not outs:
            print('No Utxo')
            return False

        for o in transaction['puts']['outputs']:
            if self.hash(o['out']) != o['hash']:
                print('out hash')
                return False
            check += o['out']['amount']

        if check != total:
            print('didnt add up %s != %s' % (check, total))
            return False

        for i in transaction['puts']['inputs']:
            m = json.dumps(i['prev_out']).encode()
            sig = binascii.unhexlify(base58.b58decode(i['sig']))
            print(pub.verify(sig, m))
        return True

# class cont(verify):
    # def __init__(self, diff, last, utxo, pool, reward, change, halve, ):
    #    self.difficulty = diff
    #    self.last_block =