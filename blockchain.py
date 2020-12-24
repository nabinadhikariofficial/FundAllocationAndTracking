import time  # for timestamp
import hashlib  # for hasing the block
import json  # for json files work
from flask import Flask, request, render_template, jsonify, Markup, session, redirect, url_for
import requests  # for requesting webpages
from uuid import uuid4  # for unique address  of the node
from urllib.parse import urlparse  # for parsing url
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re

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

        block = {'index': len(self.chain)+1,
                 'timestamp': self.time_is,
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions}
        self.transactions = []  # resseting the transaction lists
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

    def add_transaction(self, sender, receiver, amount):
        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'amount': amount})
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f"http://{node}/get_chain")
            print(response)
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


# Creating an address for the node on the given port
node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()

app.secret_key = 'key'

# database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'login'

# Intialize MySQL
mysql = MySQL(app)


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
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
        # Fetch one record and return result
        account = cursor.fetchone()
        # If account exists in accounts table in out database
        print(account)
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
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
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
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
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            cursor.execute(
                'INSERT INTO accounts VALUES (NULL, %s, %s, %s,%s)', (username, password, email, "user"))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
    elif request.method == "POST":
        msg = 'Please fill the form'
    return render_template('signup.html', msg=msg)


@app.route('/mine_block', methods=['GET', 'POST'])
def mine_block():
    if 'loggedin' in session:
        if request.method == 'GET':
            return render_template("mineblock.html")

        elif request.method == 'POST':
            previous_block = blockchain.get_previous_block()
            previous_hash = blockchain.hash(previous_block)
            # award for mining block
            blockchain.add_transaction(
                sender=node_address, receiver='XYZ', amount=1)
            proof = blockchain.proof_of_work(previous_hash)
            block = blockchain.create_block(proof, previous_hash)
            resp = Markup(
                f"Congratulations! you just mined a block. <br> This transaction will be added to Block {block['index']} <br> Proof: {block['proof']} <br> Previous hash: {block['previous_hash']} <br> Timestamp: {block['timestamp']}")
            return render_template("mineblock.html", response=resp)
    else:
        return redirect(url_for('home'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'loggedin' in session:
        return render_template('profile.html')
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
            sender = request.form["sender"]
            receiver = request.form["receiver"]
            amount = request.form["amount"]
            if (sender and receiver and amount):
                index = blockchain.add_transaction(sender, receiver, amount)
                res = f"This transaction will be added to Block {index}"
            else:
                res = "Some elements of the transaction are missing"
        return render_template('addtransaction.html', response=res)
    else:
        return redirect(url_for('home'))

# Decentralizing our Blockchain

# Connecting new nodes


@app.route('/connect_node', methods=['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected. The Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return response, 201

# Replacing the chain by the longest chain if needed


@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return response, 200


# Running the app
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
