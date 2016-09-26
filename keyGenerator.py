from Crypto.PublicKey import RSA

key = RSA.generate(2048);

def generate_private_key():
	print("Generating the private key");
	f = open("master.privatekey.der", "wb");
	f.write(key.exportKey());
	f.close();

def generate_public_key():
	print("Generating the public key");
	f = open("master.publickey.der", "wb");
	f.write(key.publickey().exportKey());
	f.close();

generate_private_key();
generate_public_key();