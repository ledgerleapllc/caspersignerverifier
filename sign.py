#!/usr/bin/env python3
##
# Written by @blockchainthomas
#

import os, sys, hashlib, base64, argparse

try:
	import ed25519
except ImportError:
	print("You must install the 'ed25519' library to use this signer.")
	print("Install using:")
	print("")
	print("python3 -m pip install ed25519")
	sys.exit(1)

try:
	import ecdsa
except ImportError:
	print("You must install the 'ecdsa' library to use this signer.")
	print("Install using:")
	print("")
	print("python3 -m pip install ecdsa")
	sys.exit(1)

class CasperSigner():
	def __init__(self):
		self.current_path = os.path.dirname(os.path.abspath(__file__))
		parser = argparse.ArgumentParser()
		parser.add_argument('args', nargs='*', help='Positional arguments for specifying message, secret key, and public key - in that order.')
		parser.add_argument('-s', action='store_true', help='This flag instructs the signer to expect a SECP256K1 keypair instead of the default ED25519.')
		args = parser.parse_args()
		self.all_args = args.args
		self.vid_type = 2 if args.s else 1
		# print(self.all_args)
		# print(self.vid_type)
		self.secret_key_file = '/etc/casper/validator_keys/secret_key.pem'
		self.public_key_file = '/etc/casper/validator_keys/public_key.pem'
		self.__secret_key_b64string = ""
		self._public_key_b64string = ""
		self._secp_verifying_key = None
		self.asn1_signature = ""
		self.message = ""
		self.signature = None
		self.verified = False

	def show_help(self):
		print("")
		print("Casper Signer")
		print("")
		print("Casper signer takes 3 arguments, the first one is required.")
		print("\n * Argument 1 is the path to the message to be signed,")
		print("   or can also be the actual message string wrapped in quotes.")
		print("\n * Argument 2 is the path to your secret key.")
		print("   This argument defaults to '/etc/casper/validator_keys/secret_key.pem'")
		print("\n * Argument 3 is the path to your public key")
		print("   This argument defaults to '/etc/casper/validator_keys/public_key.pem'")
		print("   and is required if you want to verify your signature before")
		print("   exporting it to the Casper Association. Otherwise it is optional.")
		print("")
		print("SECP256K1 is now supported. Pass in the -s flag to specify this curve.")
		print("")
		print("Examples:")
		print("")
		print('  python3 sign.py "sign this message"')
		print('  python3 sign.py /etc/casper/message.txt')
		print('  python3 sign.py "sign this message" /home/secret_key /home/public_key')
		print('  python3 sign.py -s "sign this message" /home/secp256k1_secret_key')
		print('')

	def process_args(self):
		if len(self.all_args) == 0:
			self.show_help()
			sys.exit(0)

		if len(self.all_args) > 0:
			self.message = self.all_args[0]
			if(
				'/' in self.message or
				os.path.isfile(self.message)
			):
				try:
					message_file = open(self.message, 'r')
					self.message = message_file.read().strip()
					message_file.close()
				except OSError:
					print("Could not find the message file '%s'" % self.message)
					sys.exit(2)

		if len(self.all_args) > 1:
			self.secret_key_file = self.all_args[1]
			if not os.path.isfile(self.secret_key_file):
				print("Could not find secret key '%s'" % self.secret_key_file)
				self.show_help()
				sys.exit(3)

		if len(self.all_args) > 2:
			self.public_key_file = self.all_args[2]
			if not os.path.isfile(self.public_key_file):
				print("Could not find public key '%s'" % self.public_key_file)
				self.show_help()
				sys.exit(4)

		return True

	def load_secret_key(self):
		try:
			secret_key_file_handler = open(self.secret_key_file, 'r')
		except:
			print("Cannot find secret key file '%s'" % self.secret_key_file)
			sys.exit(5)

		secret_key_read = secret_key_file_handler.readlines()
		secret_key_file_handler.close()

		for line in secret_key_read:
			if '-----' not in line:
				self.__secret_key_b64string += line.strip()

	def load_public_key(self):
		try:
			public_key_file_handler = open(self.public_key_file, 'r')
		except:
			print("Cannot find public key file '%s'. " % self.public_key_file)
			print("Warning: We will not be able to pre-check your signature before upload. If you are certain the secret key is correct, then you can ignore this message.")
			# sys.exit(6)
			return self._public_key_b64string

		public_key_read = public_key_file_handler.readlines()
		public_key_file_handler.close()

		for line in public_key_read:
			if '-----' not in line:
				self._public_key_b64string += line.strip()

		return self._public_key_b64string

	def sign(self):
		if self.vid_type == 2:
			secret_key_hex = base64.b64decode(self.__secret_key_b64string).hex()
			secret_key_hex = secret_key_hex[14:14+64]
			secret_key_bytes = bytes.fromhex(secret_key_hex)
			signing_instance = ecdsa.SigningKey.from_string(
				secret_key_bytes,
				curve = ecdsa.SECP256k1,
				hashfunc = hashlib.sha256
			)

			self._secp_verifying_key = signing_instance.get_verifying_key()

			self.signature = signing_instance.sign(
				bytes(self.message, 'utf8'),
				hashfunc = hashlib.sha256
			).hex()

			self.asn1_signature = (
				"3046" + 
				"022100" + 
				self.signature[:64] + 
				"022100" + 
				self.signature[64:]
			)
		else:
			secret_key_hex = base64.b64decode(self.__secret_key_b64string).hex()
			start_point = len(secret_key_hex) - 64 if len(secret_key_hex) - 64 > 0 else 0
			secret_key_hex = secret_key_hex[start_point:]
			secret_key_bytes = bytes.fromhex(secret_key_hex)
			signing_instance = ed25519.SigningKey(secret_key_bytes)

			self.signature = signing_instance.sign(
				bytes(self.message, 'utf8'),
				encoding = "hex"
			)

			self.signature = self.signature.decode('utf8')

		# print("\nSIGNATURE:", self.signature)
		return self.signature

	def verify(self):
		public_key_hex = base64.b64decode(self._public_key_b64string).hex()

		if self.vid_type == 2:
			start_point = len(public_key_hex) - 66 if len(public_key_hex) - 66 > 0 else 0
			public_key_hex = public_key_hex[start_point:]
			public_key_bytes = bytes.fromhex(public_key_hex)

			verifying_instance = ecdsa.VerifyingKey.from_string(
				public_key_bytes,
				curve = ecdsa.SECP256k1,
				hashfunc = hashlib.sha256
			)

			try:
				# self._secp_verifying_key.verify(
				# 	bytes.fromhex(self.signature),
				# 	bytes(self.message, 'utf8')
				# )
				verifying_instance.verify(
					bytes.fromhex(self.signature),
					bytes(self.message, 'utf8')
				)
				# print('GOOD SIGNATURE')
				self.verified = True
			except:
				self.verified = False
				# print('BAD SIGNATURE')
				print('\nPlease do not use this signature. We tested your signature using the public key specified and it did not pass. Check the file paths and the keys you specified and try again.')
		else:
			start_point = len(public_key_hex) - 64 if len(public_key_hex) - 64 > 0 else 0
			public_key_hex = public_key_hex[start_point:]
			public_key_bytes = bytes.fromhex(public_key_hex)
			verifying_instance = ed25519.VerifyingKey(public_key_bytes)

			try:
				verifying_instance.verify(
					self.signature, bytes(self.message, 'utf8'),
					encoding = 'hex'
				)
				# print('GOOD SIGNATURE')
				self.verified = True
			except ed25519.BadSignatureError:
				self.verified = False
				# print('BAD SIGNATURE')
				print('\nPlease do not use this signature. We tested your signature using the public key specified and it did not pass. Check the file paths and the keys you specified and try again.')

		return self.verified


if __name__ == "__main__":
	casigner = CasperSigner()
	casigner.process_args()
	casigner.load_secret_key()
	loaded_public_key = casigner.load_public_key()

	signature = casigner.sign()
	is_verified = False if loaded_public_key == '' else casigner.verify()

	if casigner.vid_type == 2:
		signature = casigner.asn1_signature

	with open("%s/signature" % casigner.current_path, 'w') as write_signature:
		write_signature.write(signature)

	print("\nSIGNATURE: \n")
	print(signature)
	print("\nGOOD SIGNATURE" if is_verified else "\nCOULD NOT VERIFY SIGNATURE")
