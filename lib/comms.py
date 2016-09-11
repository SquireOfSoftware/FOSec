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
        print("IV: ", IV, len(IV));
        #would you use a random number and wrap round to 56 bits?
        self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CBC, IV);
        print("length of hash: ", len(self.shared_hash));
        #print("type of hash: ", type(shared_hash));
        #self.HMAC is using half of the shared key as the MAC(unique ID) and Hashed it
        self.HMAC = HMAC.new(self.shared_hash[32:], digestmod = SHA256)
		
    def send(self, data):
        if self.cipher:
            IV = Random.get_random_bytes(AES.block_size);
            #self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CBC, IV);

            # data must be padded
			#Hashed the message as part of the HMAC
            hmac = self.HMAC;
            #print("hmac: {} {}", hmac.digest(), len(hmac.digest()));

            #data = data[:-data[-1]]
			#HMAC has been appended to the message to ensure integrity
            #message = IV + data + hmac.digest();
            IV = self.cipher.IV;
            message = IV + data + hmac.digest();
            #message = IV + bytes(hmac.hexdigest() + data.decode("ascii"), "ascii");
            print("message: ", message);
            print("message length: ", len(message));
            
            # pad message here
            pad_length = AES.block_size - (len(message) % AES.block_size);
            message += bytes([pad_length])*(pad_length);
            #message = ANSI_X923_pad(message, AES.block_size);
            print("padded message: ", message);
            #print("pad length: ", pad_length);

            #message = message[:-message[-1]];

            encrypted_data = self.cipher.encrypt(message);# + hmac.digest());
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data
        print("sending cipher: ", self.cipher);
        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'));
        #print("packet type: ", type(pkt_len_packed));
        print("packet len packed: ", pkt_len_packed);
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        #pkt_len = unpacked_contents[len(unpacked_contents) - 1];
        #print("length of hash: ", len(self.shared_hash));
        pkt_len = unpacked_contents[0];
        print("unpacked_contents: ", unpacked_contents);
        print("pkt_len: ", pkt_len);
        # last bit contains the length of the original message
        # need to split this out also take out the 32 bit hmac
        print("unpacking now");
        encrypted_data = self.conn.recv(pkt_len)
        IV = encrypted_data[:AES.block_size];
        #self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CBC, IV);
        # this bit is correct
        print("encrypted_data: ", encrypted_data);
        print("self.cipher: ", self.cipher);
        if self.cipher:
            print("decrypting now");
            IV = encrypted_data[:AES.block_size];
            #print("iv comparison: {} {} ", IV, self.cipher.iv)
            data = self.cipher.decrypt(encrypted_data[AES.block_size:]);
            print("decrypted data: ", data);
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data;
        IV = data[:AES.block_size];
        #data = ANSI_X923_unpad(data, AES.block_size);
        print("IV, ", IV);
        print("data: ", data[16:]);
        #data = data[16:];
        #removing padding

        pad_length = data[-1];
        print("pad_length: ", pad_length);
        print("original message: ", data[AES.block_size:len(data) - pad_length]);
        data_with_hmac = data[AES.block_size: len(data) - pad_length];
        print("data_with_hmac: ", data_with_hmac);
        #split the HMAC from 
        hmac = data_with_hmac[len(data_with_hmac) - AES.block_size:];
        print("hmac: ", hmac);
        cmd = data_with_hmac[:-AES.block_size];
        print("cmd: ", cmd, len(cmd), type(cmd));
        #data = data_with_hmac[:len(data_with_hmac) - AES.block_size];
        #print("data: ", data_with_hmac[:len(data_with_hmac) - AES.block_size], len(data_with_hmac));
        # this needs to be the command for the packet
        #return data[AES.block_size:-pad_length];
        #return cmd;
        return data;
    def close(self):
        self.conn.close()
