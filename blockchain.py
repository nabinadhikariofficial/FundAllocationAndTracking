import datetime  # for timestamp
import hashlib  # for hasing the block
import json  # for json files work
<<<<<<< HEAD
# import requests  # for requesting among nodes for the json files
from flask import Flask, request
=======
from flask import Flask 
>>>>>>> 171d953375d8f8b784433b5fdf4bf3f3144197b5


class Blockchain:  # defining our blockchain class
    def __init__(self):
        self.chain = []
        self.trasactions = []
        self.time_is = str(datetime.datetime.now())
        # proof=1, for the genesis block.
        self.create_block(proof=1, previous_hash='0')
       # self.nodes = set()  # crates nodes unordederd set

    def create_block(self, proof, previous_hash):  # create a block

        block = {'index': len(self.chain)+1,
                 'timestamp': self.time_is,
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'trasactions': self.trasactions}
        self.chain.append(block)
        self.trasactions = []  # to empty the mempool after the transaction are added

        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_hash):  # hasing function to find the nonce
        new_proof = 1
        check_proof = False
        while check_proof is False:
            temp_block = self.block_for_proof(new_proof, previous_hash)
            hash_operation = self.hash(temp_block)
            if hash_operation[:3] == '000':
                check_proof = True

            else:
                new_proof = new_proof+1

        return new_proof

    def get_time(self):
        self.time_is = str(datetime.datetime.now())
        return 1

    def block_for_proof(self, proof, previous_hash):
        self.get_time()
        temp_block = {'index': len(self.chain)+1,
                      'timestamp': self.time_is,
                      'proof': proof,
                      'previous_hash': previous_hash,
                      'trasactions': self.trasactions
                      }

        return temp_block

    def hash(self, block):
        # use json.dumps for str during web
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def add_transactions_to_mempool(self, sender, reciver, amount, remarks):
        self.trasactions.append({'sender': sender,
                                 'reciver': reciver,
                                 'amount': amount,
                                 'remarks': remarks})

        return 1


app = Flask(__name__)

# creating node address on the port 5000


blockchain = Blockchain()


@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_hash = blockchain.hash(previous_block)
    proof = blockchain.proof_of_work(previous_hash)
    my_worth = blockchain.add_transactions_to_mempool(
        'blockchain', 'me', '1000', 'for mining')
    block = blockchain.create_block(proof, previous_hash)

    response = {'message': "New block has been mined and added",
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'trasactions': block['trasactions']}
    return response, 200


@app.route('/get_chain', methods=['GET'])
def get_chain():

    response = {'chain': blockchain.chain,
                'len': len(blockchain.chain)}
    return response, 200


@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'reciver', 'amount', 'remarks']
    if not all(key in json for key in transaction_keys):
        return 'some transaction key donot match', 400
    index = blockchain.add_transactions_to_mempool(
        json['sender'], json['reciver'], json['amount'], json['remarks'])
    # response = {your transaction has been added to the mem pool and in next block'}
   # return jsonify(response), 201
    return 'your txn is added to the mempool and will be added to next block', 201


app.run(host='0.0.0.0', port=5000)
