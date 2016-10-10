import os

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from lib.crypto_utils import ANSI_X923_unpad

RSA_ENCRYPTION_SIZE = 256

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out

    masters_private_key = RSA.importKey(open('master.privatekey.der').read());

    # received file structure
    # RSA(iv) + AES(file) + digest
    # RSA = 256 bytes, digest = 256 bytes

    # taking out the encrypted IV
    rsa_encrypted_iv = f[:RSA_ENCRYPTION_SIZE]
    iv = masters_private_key.decrypt(rsa_encrypted_iv)

    # taking out the encrypted file that is wedged between IV and digest
    encrypted_data = f[RSA_ENCRYPTION_SIZE:-SHA256.digest_size]

    # decrypt the data based on IV located
    decrypted_data = AES.new(str(iv)[:16], AES.MODE_CBC, iv).decrypt(encrypted_data)
    decrypted_data = ANSI_X923_unpad(decrypted_data, AES.block_size)

    # take out the digest
    digest = f[-SHA256.digest_size:]

    # generate our own digest
    decrypted_data_hash = SHA256.new(decrypted_data).digest()

    if digest != decrypted_data_hash:
        print("This file has been tampered with")
    else:
        decoded_text = str(decrypted_data, 'ascii')
        print(decoded_text);

if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
