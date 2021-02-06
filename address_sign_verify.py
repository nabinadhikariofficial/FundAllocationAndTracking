import bitcoin

from pycoin.ecdsa import generator_secp256k1, sign, verify
import hashlib
from blockchain import *



def sha3_256Hash(msg):
  msg = str(msg)
  print("string msg:",msg)
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

if valid_private_key == False:
  # Generate a random private key
  while not valid_private_key:
    private_key = bitcoin.random_key()
    decoded_private_key = bitcoin.decode_privkey(private_key, 'hex')
    valid_private_key = 0 < decoded_private_key < bitcoin.N
else:
  private_key = blockchain.

print("Private Key (hex) is: ", private_key)


# Multiply the EC generator point G with the private key to get a public key point
public_key = bitcoin.fast_multiply(bitcoin.G, decoded_private_key)

# Encode as hex, prefix 04
hex_encoded_public_key = bitcoin.encode_pubkey(public_key, 'hex')

# Compress public key, adjust prefix depending on whether y is even or odd
(public_key_x, public_key_y) = public_key
compressed_prefix = '02' if (public_key_y % 2) == 0 else '03'
hex_compressed_public_key = compressed_prefix + (bitcoin.encode(public_key_x, 16).zfill(64))
print("Compressed Public Key (hex) is:", hex_compressed_public_key)

# Generate Wallet address from public key
print("Wallet Address (b58check) is:", bitcoin.pubkey_to_address(public_key))



msg = blockchain.Blockchain.create_block.block
signature = signECDSAsecp256k1(msg, decoded_private_key)
print("Message:", msg)


hex_encoded_signature = bitcoin.encode_sig(23,signature[0], signature[1])
print("Signature(Hex):",hex_encoded_signature )

# ECDSA verify signature (using the curve secp256k1 + SHA3-256)
valid = verifyECDSAsecp256k1(msg, signature, public_key)
print("\nMessage:", msg)
print("Signature valid?", valid)

