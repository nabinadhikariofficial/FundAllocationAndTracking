import matplotlib.pyplot as plt  # for data visualization
import time  # for timestamp
import hashlib  # for hasing the block
import json  # for json files work
from flask import Flask, request, render_template, jsonify, Markup, session, redirect, url_for
import requests  # for requesting webpages
from uuid import uuid4  # for unique address  of the node
from urllib.parse import urlparse  # for parsing url
from datetime import timedelta  # for time difference
import mysql.connector
import re
import bitcoin
from pycoin.ecdsa import generator_secp256k1, sign, verify
import matplotlib
matplotlib.use('Agg')

# Building a Blockchain


class Blockchain:  # defining our blockchain class
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.time_is = str(int(time.time()))
        # proof=1, for the genesis block.
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()  # creates nodes set for the given nodes connected in the network
        self.count = 1

    def create_block(self, proof, previous_hash):  # create a block

        block = {
            'index': len(self.chain)+1,
            'timestamp': self.time_is,
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }

        self.transactions = []  # resseting the transaction lists
        self.count = 1  # restting transaction count
        self.chain.append(block)
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
        self.time_is = str(int(time.time()))

    def block_for_proof(self, proof, previous_hash):
        self.get_time()
        temp_block = {'index': len(self.chain)+1,
                      'timestamp': self.time_is,
                      'proof': proof,
                      'previous_hash': previous_hash,
                      'transactions': self.transactions
                      }
        return temp_block

    def hash(self, block):
        # use json.dumps for str during web
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transaction(self, sender, receiver, amount, signature, purpose, detail):
        self.transactions.append({'index': self.count, 'sender': sender,
                                  'receiver': receiver,
                                  'amount': amount,
                                  'purpose': purpose.lower(),
                                  'detail': detail,
                                  'transaction_time': str(int(time.time())),
                                  'signature': signature})
        previous_block = self.get_previous_block()
        self.count = self.count+1  # increasing count value in transaction
        return previous_block['index'] + 1

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f"http://{node}/get_chain_only")
            if response.status_code == 200:
                length = response.json()['len']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False


# Creating a Web App
app = Flask(__name__)
app.secret_key = 'key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    minutes=2)  # session logout after 2 minutes of idle case

# Creating an address for the node on the given port
node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()

# database connection details below
mydb = mysql.connector.connect(
    host="34.68.7.71",
    user="root",
    passwd="Gs92p421dOk7mNeL",
    database="login"
)

# host address and port
host_add = '127.0.0.1'
port_add = 5001

# making cursor
cursor = mydb.cursor(dictionary=True)

# Multiply the EC generator point G with the private key to get a public key point


def public_key_gen(temp_private_key):
    decoded_private_key = bitcoin.decode_privkey(
        temp_private_key, 'hex')
    public_key = bitcoin.fast_multiply(bitcoin.G, decoded_private_key)
    return public_key
# signature conversion functions


def sha3_256Hash(msg):
    msg = str(msg)
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")


def signECDSAsecp256k1(msg, decoded_private_key):
    msgHash = sha3_256Hash(msg)
    signature = sign(generator_secp256k1, decoded_private_key, msgHash)
    return signature


def verifyECDSAsecp256k1(msg, signature, public_key):
    msgHash = sha3_256Hash(msg)
    valid = verify(generator_secp256k1, public_key, msgHash, signature)
    return valid


def check_signature():
    return

# Mining a new block


@app.route('/home', methods=['GET', 'POST'])
def home():
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if 'loggedin' in session:
        return redirect(url_for('profile'))
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # converting password into sha 256 to check
        password = hashlib.sha256(password.encode()).hexdigest()
        # Check if account exists using MySQL
        cursor.execute(
            'SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
        # Fetch one record and return result
        account = cursor.fetchone()
        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session.permanent = True
            session['loggedin'] = True
            session['id'] = account['id']
            # some work left here but done with dictcursor
            session['username'] = account['username']
            # connect nodes and check for the longest chain
            connect_node()
            msg = replace_chain()
            # Redirect to profile page
            return redirect(url_for('profile'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    return render_template('homepage.html', msg=msg)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    if request.method == "POST" and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
    # Check if account exists using MySQL
        cursor.execute(
            'SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
    # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # converting password into sha 256 to store
            password = hashlib.sha256(password.encode()).hexdigest()
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            # To generate new private key
            temp_private_key = bitcoin.random_key()
            (public_key_x, public_key_y) = public_key_gen(temp_private_key)
            # compressing public key Compress public key, adjust prefix depending on whether y is even or odd
            compressed_prefix = '02' if (public_key_y % 2) == 0 else '03'
            public_key_comp = compressed_prefix + \
                (bitcoin.encode(public_key_x, 16).zfill(64))
            cursor.execute(
                'INSERT INTO accounts VALUES (NULL,%s,%s,%s,%s,%s,%s,%s)', (username, password, email, "user", str(public_key_x), str(public_key_y), str(public_key_comp)))
            mydb.commit()
            msg = 'You have successfully registered! Your private key is:\n' + temp_private_key
    elif request.method == "POST":
        msg = 'Please fill the form'
    return render_template('signup.html', msg=msg)


@app.route('/mine_block', methods=['GET', 'POST'])
def mine_block():
    response = {'message': '', 'blockinfo': ''}
    if 'loggedin' in session:
        if request.method == 'GET':
            connect_node()
            response = replace_chain()
            return render_template("mineblock.html", response=response)

        elif request.method == 'POST':
            previous_block = blockchain.get_previous_block()
            previous_hash = blockchain.hash(previous_block)
            # award for mining block
            blockchain.add_transaction(
                sender=node_address, receiver=session['username'], amount=1, signature="mined", purpose="mining", detail="Amount got from the mining")
            proof = blockchain.proof_of_work(previous_hash)
            block = blockchain.create_block(proof, previous_hash)
            response['blockinfo'] = Markup(
                f"Congratulations! you just mined a block. <br> This transaction will be added to Block {block['index']} <br> Proof: {block['proof']} <br> Previous hash: {block['previous_hash']} <br> Timestamp: {block['timestamp']}")
            return render_template("mineblock.html", response=response)
    else:
        return redirect(url_for('home'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM accounts WHERE id = %s',
                       (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    else:
        return redirect(url_for('home'))
# Getting the full Blockchain


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('home'))


@app.route('/get_chain_only', methods=['GET'])
def get_chain_only():

    response = {'chain': blockchain.chain,
                'len': len(blockchain.chain)}
    return response, 200


@app.route('/get_chain', methods=['GET'])
def get_chain():
    if 'loggedin' in session:
        resp = [{"chain": blockchain.chain}]
        return render_template('viewtransaction.html', response=resp[0])
    else:
        return redirect(url_for('home'))
# Checking if the Blockchain is valid


@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {
            'message': 'We have a problem. The Blockchain is not valid.'}
    return response, 200

# Adding a new transaction to the Blockchain


@app.route('/add_transaction', methods=['POST', 'GET'])
def add_transaction():
    res = "The upcoming transaction is added to next block"
    if 'loggedin' in session:
        if request.method == "POST":
            receiver = request.form["receiver"]
            amount = request.form["amount"]
            private_key = request.form["private_key"]
            purpose = request.form["purpose"]
            detail = request.form["detail"]
            (temp_public_key_x, temp_public_key_y) = public_key_gen(private_key)
            cursor.execute(
                'SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()
            sender = account['public_key_comp']
            cursor.execute(
                'SELECT * FROM accounts WHERE username = %s', (receiver,))
            rec_account = cursor.fetchone()
            if (rec_account):
                receiver = rec_account['public_key_comp']
                msg = {'sender': sender, 'receiver': receiver, 'amount': amount}
                if (sender and receiver and amount and purpose and detail):
                    # checking if private key is true or not
                    if (str(temp_public_key_x) == account['public_key_x'] and str(temp_public_key_y) == account['public_key_y']):
                        # adding signature to the transaction
                        signature = signECDSAsecp256k1(
                            msg, bitcoin.decode_privkey(private_key, 'hex'))
                        index = blockchain.add_transaction(
                            sender, receiver, amount, signature, purpose, detail)
                        res = f"This transaction will be added to Block {index}"
                    else:
                        res = "Incorrect private key!!!"
            else:
                res = "Reciever Username Not found!!!"
        return render_template('addtransaction.html', response=res)
    else:
        return redirect(url_for('home'))


@app.route('/track_transaction', methods=['POST', 'GET'])
def track_transaction():
    if 'loggedin' in session:
        heading = ''
        search_data = {'S.no': '',
                       'sender': '',
                       'receiver': '',
                       'amount': '',
                       'time': ''}
        loc = ""
        fund = {'allocated': 0.0, 'spended': 0.0}
        if request.method == "POST":
            heading = ('S.no', 'Sender', 'Receiver', 'Amount', 'Time')
            search_key = request.form["search_key"]
            search_data = search(search_key)
            time_data = []
            amount = []
            for data in search_data:
                if (data['sender'] == data['receiver']):
                    fund['allocated'] = fund['allocated']+float(data['amount'])
                else:
                    fund['spended'] = fund['spended']+float(data['amount'])
                time_data.append(data['time'])
                # data conversion as it is in string
                amount.append(float(data['amount']))
            strFile = "static/img/plot.png"
            plt.style.use('seaborn')
            plt.xlabel('Time', fontsize=14)
            plt.ylabel('Amount', fontsize=14)
            plt.title('Transaction History', fontsize=14)
            plt.xticks(rotation='vertical', fontsize=8)
            plt.subplots_adjust(bottom=0.4)
            plt.plot(time_data, amount, color='green', marker='o')
            plt.savefig(strFile)
            plt.close()
            loc = "\static\img\plot.png?"+str(int(time.time()))
            if len(search_data) == 0:
                heading = "Nodata"
        else:
            pass
        return render_template('tracktransaction.html', search_data=search_data, heading=heading, loc=loc, fund=fund)
    else:
        return redirect(url_for('home'))

# searching


def search(search_key):
    searched_data = []
    count = 1
    for blocks in blockchain.chain:
        for transaction in blocks['transactions']:
            if search_key.lower() in transaction['purpose']:
                if (transaction['purpose'] == 'mining'):
                    sender_name = transaction['sender']
                    receiver_name = transaction['receiver']
                else:
                    cursor.execute(
                        'SELECT * FROM accounts WHERE public_key_comp = %s', (transaction['sender'],))
                    sen_account = cursor.fetchone()
                    sender_name = sen_account['username']
                    cursor.execute(
                        'SELECT * FROM accounts WHERE public_key_comp = %s', (transaction['receiver'],))
                    rev_account = cursor.fetchone()
                    receiver_name = rev_account['username']
                data = {'S.no': count,
                        'sender': sender_name,
                        'receiver': receiver_name,
                        'amount': transaction['amount'],
                        'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(transaction['transaction_time'])))}  # epoch time coneversion is done
                searched_data.append(data)
                count += 1
    return searched_data


# Decentralizing our Blockchain
# Connecting new nodes


def connect_node():
    with open("nodes.json",) as f:
        nodes = json.load(f)
    for node in nodes['nodes']:
        if (urlparse(node).netloc[-4:] == port_add):
            continue
        blockchain.add_node(node)
    return

# Replacing the chain by the longest chain if needed
# main chain replacing algorithm can be changed accorfing to the need


def replace_chain():
    response = {'message': '', 'blockinfo': ''}
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response['message'] = "The nodes had different chains so the chain was replaced by the longest one."
    else:
        response['message'] = "All good. The chain is the largest one."
    return response


# Running the app
if __name__ == "__main__":
    app.run(host=host_add, port=port_add, debug=True)
