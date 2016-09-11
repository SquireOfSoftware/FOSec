import struct
import codecs
import base64

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random  
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)			
			#Shared key is in hash format                           
            self.shared_hash = codecs.decode(self.shared_hash, 'hex_codec')

        IV = Random.get_random_bytes((AES.block_size));
        #would you use a random number and wrap round to 56 bits?
        self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CBC, IV);

        #self.HMAC is using half of the shared key as the MAC(unique ID) and Hashed it
        self.HMAC = HMAC.new(self.shared_hash[32:], digestmod = SHA256)
		
    def send(self, data):
        if self.cipher:
            # generate new IV for each message sent
            IV = Random.get_random_bytes(AES.block_size);
            self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CBC, IV);

            # data must be padded
			#Hashed the message as part of the HMAC
            hmac = self.HMAC;

			#HMAC has been appended to the message to ensure integrity
            IV = self.cipher.IV;
            message = data + hmac.digest();
            
            # pad message here
            message = ANSI_X923_pad(message, AES.block_size);
            
            # IV must be read to decrypt the message
            encrypted_data = IV + self.cipher.encrypt(message);

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data
        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'));
        
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        
        pkt_len = unpacked_contents[0];

        encrypted_data = self.conn.recv(pkt_len);

        if self.cipher:
            IV = encrypted_data[:AES.block_size];
            self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CBC, IV);

            padded_data = self.cipher.decrypt(encrypted_data[AES.block_size:]);

            # remove the padding
            unpadded_data_with_hmac = ANSI_X923_unpad(padded_data, AES.block_size);

            # take out the main contents which is largely composed of the hmac
            data = unpadded_data_with_hmac[:-32];

            # take out the hmac
            received_hmac = unpadded_data_with_hmac[-32:];
            #print("received_hmac: ", received_hmac);
            generated_hmac = HMAC.new(self.shared_hash[32:], digestmod = SHA256).digest();
            #print("generated_hmac: ", generated_hmac);
            if (received_hmac != generated_hmac):
                print("TAMPERED MESSAGE");

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else: #used by other methods to be triggered
            data = encrypted_data;
        
        return data;
    def close(self):
        self.conn.close()
