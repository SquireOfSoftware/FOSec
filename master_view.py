import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out

    masters_private_key = RSA.importKey(open('master.privatekey.der').read());

    pkcs_cipher = PKCS1_v1_5.new(masters_private_key);
    decryption_error = None;
    hexdigest = f[-20:];

    encrypted_data = f[:-20];
    decrypted_file = pkcs_cipher.decrypt(encrypted_data, decryption_error);
    decrypted_file_hash = SHA.new(decrypted_file).digest();

    if decryption_error is not None:
        print("There is a problem with decrypting this file.");
    elif hexdigest != decrypted_file_hash:
        print("This file has been tampered with");
    else:
        decoded_text = str(decrypted_file, 'ascii');
        print(decoded_text);


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
