import os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Cipher import AES

from lib.crypto_utils import ANSI_X923_pad

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []
masters_public_key = RSA.importKey(open('master.publickey.der').read())

###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master
    hashed_data = SHA256.new(data).digest();

    # generate iv from RSA publickey
    # generate AES CBC from RSA and iv
    # encrypt AES key with RSA
    # RSA(iv) + AES(file) + digest

    iv = Random.get_random_bytes(AES.block_size)
    aes_encrypted_data = AES.new(str(iv)[:16], AES.MODE_CBC, iv).encrypt(ANSI_X923_pad(data, AES.block_size))

    rsa_encrypted_iv = masters_public_key.encrypt(iv, "")[0]

    return rsa_encrypted_iv + aes_encrypted_data + hashed_data;

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here
    # Naive verification by ensuring the first line has the "passkey"
    message = f[256:]
    master_signature = f[:256]

    hash = SHA256.new(message)
    verifier = PKCS1_PSS.new(masters_public_key);
    is_valid = verifier.verify(hash, master_signature);

    return is_valid;

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
