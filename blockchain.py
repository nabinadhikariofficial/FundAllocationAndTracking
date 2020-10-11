import datetime  # for timestamp
import hashlib  # for hasing the block
import json  # for json files work
from uuid import uuid4  # generate pseudo random numers..
from flask import Flask 


class Blockchain:  # defining our blockchain class
    def __init__(self):
        self.chain = []
        self.trasactions = []
        self.time_is=str(datetime.datetime.now())
        # proof=1, for the genesis block.
        self.create_block(proof=1, previous_hash='0')
       # self.nodes = set()  # crates nodes unordederd set

    def create_block(self, proof, previous_hash):  # create a block
        
                block = {'index': len(self.chain)+1,
               'timestamp':self.time_is ,
               'proof': proof,
               'previous_hash': previous_hash,
               'trasactions': self.trasactions}
                self.chain.append(block)
                return block
            

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_hash):  # hasing function to find the nonce
        new_proof = 1
        check_proof = False
        while check_proof is False:
            temp_block=self.block_for_proof(new_proof,previous_hash)
            hash_operation = self.hash(temp_block)
            if hash_operation[0]=='0':
                check_proof = True
                
            else:
                new_proof= new_proof+1
                check_proof=False
        return new_proof
       
        
        
    def get_time(self):
        self.time_is=str(datetime.datetime.now())
        return 1
  
    
    def block_for_proof(self,proof,previous_hash):
        time_check=False
        if time_check== False:
            time_check=True
        else:
            temp_block={'index': len(self.chain)+1,
                   'timestamp': self.time_is,
                    'proof': proof,
                   'previous_hash': previous_hash,
                   'trasactions': self.trasactions
                   }
            return temp_block

    def hash(self,block):
        encoded_block=json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
     
    
   
        
    

app=Flask(__name__)

# creating node address on the port 5000




blockchain=Blockchain()

@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block=blockchain.get_previous_block()
    previous_hash=blockchain.hash(previous_block)
    proof = blockchain.proof_of_work(previous_hash)
 
    block = blockchain.create_block(proof, previous_hash)
  
    response={'message':"New block has been mined and added",
               'index':block['index'],
               'timestamp':block['timestamp'],
               'proof': block['proof'],
               'previous_hash': block['previous_hash'],
               'trasactions':block['trasactions']}
    return response, 200

@app.route('/get_chain', methods=['GET'])
def get_chain():
    
    response={'chain':blockchain.chain,
              'len':len(blockchain.chain)}
    return response, 200
    
app.run(host='0.0.0.0', port=5000)

    
    
    
        
