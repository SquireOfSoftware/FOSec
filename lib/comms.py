import struct
import codecs
import random

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
			#PRNG Seed is taken from 32 bits of the shared key
            random.seed(self.shared_hash[:32])

		
    def send(self, data):
        if self.cipher:
            # generate new IV for each message sent
            IV = Random.get_random_bytes(AES.block_size);
            self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CBC, IV);

			#Create a unique session ID 
            ID = str(int(random.random()*pow(10,12))).encode("ascii")[:16]
			
            data_id = data + ID
            hmac_data_id = HMAC.new(self.shared_hash[32:], data_id, digestmod=SHA256)
            hmac_digest_data_id = data_id + hmac_data_id.digest()
			
			#HMAC has been appended to the message to ensure integrity
            IV = self.cipher.IV;
            message = data + hmac.digest();
            
            # pad message here
            message = ANSI_X923_pad(hmac_digest_data_id, AES.block_size);
            
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
            
			# decrypt the message
            padded_data = self.cipher.decrypt(encrypted_data[AES.block_size:]);

            # remove the padding
            hmac_digest_data_id = ANSI_X923_unpad(padded_data, AES.block_size);

            # take out the main contents which is largely composed of the hmac
            data_id = hmac_digest_data_id[:-32];
            # take out the hmac
            received_hmac = hmac_digest_data_id[-32:];
			
			# take out the session ID 
            recieved_id = data_id[-16:]
            data = data_id[:-16]
			
			#Reproduce SessionID to compare to the recieved one
            generated_id = str(int(random.random()*pow(10,12))).encode("ascii")[:16]
			
			
            #print("received_hmac: ", received_hmac);
            generated_hmac = HMAC.new(self.shared_hash[32:], data_id, digestmod=SHA256).digest();
			
            #print("generated_hmac: ", generated_hmac);
            if (received_hmac != generated_hmac):
                print("TAMPERED MESSAGE");
				#self.close()

            if (recieved_id != generated_id): 
                print("MESSAGE REPLAYED")
				#self.close()
				
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else: #used by other methods to be triggered
            data = encrypted_data;
        
        return data;
    def close(self):
        self.conn.close()
