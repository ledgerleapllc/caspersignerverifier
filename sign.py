#!/usr/bin/env python3
##
# Written by @blockchainthomas
#

import os, sys, hashlib, operator, base64, argparse

try:
	import ecdsa
except ImportError:
	print("You must install the 'ecdsa' library to use this signer.")
	print("Install using:")
	print("")
	print("python3 -m pip install ecdsa")
	sys.exit(1)

class BColors():
	blue = '\033[94m'
	green = '\033[92m'
	yellow = '\033[93m'
	red = '\033[91m'
	red2 = '\033[31m'
	purple = '\033[0;95m'
	cyan = '\033[0;96m'
	end = '\033[0m'

class Ed25519:
	__version__ = "1.0.dev0"
	PY3 = sys.version_info[0] == 3
	b = 256
	q = 2 ** 255 - 19
	l = 2 ** 252 + 27742317777372353535851937790883648493
	ident = (0, 1, 1, 0)
	Bpow = []
	By = None
	Bx = None
	B = None
	d = None
	I = None

	def __init__(self):
		if self.PY3:
			self.indexbytes = operator.getitem
			self.intlist2bytes = bytes
			self.int2byte = operator.methodcaller("to_bytes", 1, "big")
		else:
			self.int2byte = chr
			range = xrange  # noqa: F821

			def indexbytes(buf, i):
				return ord(buf[i])

			def intlist2bytes(_l):
				return b"".join(chr(c) for c in _l)

		self.d = -121665 * self.inv(121666) % self.q
		self.I = pow(2, (self.q - 1) // 4, self.q)
		self.By = 4 * self.inv(5)
		self.Bx = self.xrecover(self.By)
		self.B = (self.Bx % self.q, self.By % self.q, 1, (self.Bx * self.By) % self.q)
		self.make_Bpow()

	def make_Bpow(self):
		P = self.B
		for i in range(253):
			self.Bpow.append(P)
			P = self.edwards_double(P)

	def H(self, m):
		return hashlib.sha512(m).digest()

	def dec_to_hex(self, dec):
		return hex(dec).lstrip("0x")

	def pow2(self, x, p):
		"""== pow(x, 2**p, q)"""
		while p > 0:
			x = x * x % self.q
			p -= 1

		return x

	def inv(self, z):
		r"""$= z^{-1} \mod self.q$, for z != 0"""
		# Adapted from curve25519_athlon.c in djb's Curve25519.
		z2 = z * z % self.q  # 2
		z9 = self.pow2(z2, 2) * z % self.q  # 9
		z11 = z9 * z2 % self.q  # 11
		z2_5_0 = (z11 * z11) % self.q * z9 % self.q  # 31 == 2^5 - 2^0
		z2_10_0 = self.pow2(z2_5_0, 5) * z2_5_0 % self.q  # 2^10 - 2^0
		z2_20_0 = self.pow2(z2_10_0, 10) * z2_10_0 % self.q  # ...
		z2_40_0 = self.pow2(z2_20_0, 20) * z2_20_0 % self.q
		z2_50_0 = self.pow2(z2_40_0, 10) * z2_10_0 % self.q
		z2_100_0 = self.pow2(z2_50_0, 50) * z2_50_0 % self.q
		z2_200_0 = self.pow2(z2_100_0, 100) * z2_100_0 % self.q
		z2_250_0 = self.pow2(z2_200_0, 50) * z2_50_0 % self.q  # 2^250 - 2^0

		return self.pow2(z2_250_0, 5) * z11 % self.q  # 2^255 - 2^5 + 11 = q - 2

	def xrecover(self, y):
		xx = (y * y - 1) * self.inv(self.d * y * y + 1)
		x = pow(xx, (self.q + 3) // 8, self.q)

		if (x * x - xx) % self.q != 0:
			x = (x * self.I) % self.q

		if x % 2 != 0:
			x = self.q - x

		return x

	def edwards_add(self, P, Q):
		# This is formula sequence 'addition-add-2008-hwcd-3' from
		# http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
		(x1, y1, z1, t1) = P
		(x2, y2, z2, t2) = Q

		a = (y1 - x1) * (y2 - x2) % self.q
		b = (y1 + x1) * (y2 + x2) % self.q
		c = t1 * 2 * self.d * t2 % self.q
		dd = z1 * 2 * z2 % self.q
		e = b - a
		f = dd - c
		g = dd + c
		h = b + a
		x3 = e * f
		y3 = g * h
		t3 = e * h
		z3 = f * g

		return (x3 % self.q, y3 % self.q, z3 % self.q, t3 % self.q)

	def edwards_double(self, P):
		# This is formula sequence 'dbl-2008-hwcd' from
		# http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
		(x1, y1, z1, t1) = P

		a = x1 * x1 % self.q
		b = y1 * y1 % self.q
		c = 2 * z1 * z1 % self.q
		# dd = -a
		e = ((x1 + y1) * (x1 + y1) - a - b) % self.q
		g = -a + b  # dd + b
		f = g - c
		h = -a - b  # dd - b
		x3 = e * f
		y3 = g * h
		t3 = e * h
		z3 = f * g

		return (x3 % self.q, y3 % self.q, z3 % self.q, t3 % self.q)

	def scalarmult(self, P, e):
		if e == 0:
			return self.ident

		Q = self.scalarmult(P, e // 2)
		Q = self.edwards_double(Q)
		if e & 1:
			Q = self.edwards_add(Q, P)

		return Q

	def scalarmult_B(self, e):
		e = e % self.l
		P = self.ident
		for i in range(253):
			if e & 1:
				P = self.edwards_add(P, self.Bpow[i])
			e = e // 2
		assert e == 0, e

		return P

	def encodeint(self, y):
		bits = [(y >> i) & 1 for i in range(self.b)]

		return b"".join(
			[
				self.int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
				for i in range(self.b // 8)
			]
		)

	def encodepoint(self, P):
		(x, y, z, t) = P
		zi = self.inv(z)
		x = (x * zi) % self.q
		y = (y * zi) % self.q
		bits = [(y >> i) & 1 for i in range(self.b - 1)] + [x & 1]

		return b"".join(
			[
				self.int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
				for i in range(self.b // 8)
			]
		)

	def bit(self, h, i):
		return (self.indexbytes(h, i // 8) >> (i % 8)) & 1

	def publickey(self, sk):
		if not type(sk) == bytes:
			sk = bytes.fromhex(sk)

		h = self.H(sk)
		a = 2 ** (self.b - 2) + sum(2 ** i * self.bit(h, i) for i in range(3, self.b - 2))
		A = self.scalarmult_B(a)

		return self.encodepoint(A)

	def validatorid(self, publickey):
		if type(publickey) == bytes:
			return "01" + publickey.hex()

		return "01" + publickey

	def Hint(self, m):
		h = self.H(m)

		return sum(2 ** i * self.bit(h, i) for i in range(2 * self.b))

	def calculate_signature(self, m, sk, pk):
		h = self.H(sk)
		a = 2 ** (self.b - 2) + sum(2 ** i * self.bit(h, i) for i in range(3, self.b - 2))
		r = self.Hint(
			self.intlist2bytes([self.indexbytes(h, j) for j in range(self.b // 8, self.b // 4)]) + m
		)
		R = self.scalarmult_B(r)
		S = (r + self.Hint(self.encodepoint(R) + pk + m) * a) % self.l

		return self.encodepoint(R) + self.encodeint(S)

	def isoncurve(self, P):
		(x, y, z, t) = P

		return (
			z % self.q != 0
			and x * y % self.q == z * t % self.q
			and (y * y - x * x - z * z - self.d * t * t) % self.q == 0
		)

	def decodeint(self, s):
		return sum(2 ** i * self.bit(s, i) for i in range(0, self.b))

	def decodepoint(self, s):
		y = sum(2 ** i * self.bit(s, i) for i in range(0, self.b - 1))
		x = self.xrecover(y)

		if x & 1 != self.bit(s, self.b - 1):
			x = self.q - x

		P = (x, y, 1, (x * y) % self.q)

		if not self.isoncurve(P):
			raise ValueError("decoding point that is not on curve")

		return P

	def checkvalid(self, s, m, pk):
		if len(s) != self.b // 4:
			raise ValueError("signature length is wrong")

		if len(pk) != self.b // 8:
			raise ValueError("public-key length is wrong")

		R = self.decodepoint(s[: self.b // 8])
		A = self.decodepoint(pk)
		S = self.decodeint(s[self.b // 8 : self.b // 4])
		h = self.Hint(self.encodepoint(R) + pk + m)

		(x1, y1, z1, t1) = P = self.scalarmult_B(S)
		(x2, y2, z2, t2) = Q = self.edwards_add(R, self.scalarmult(A, h))

		if (
			not self.isoncurve(P)
			or not self.isoncurve(Q)
			or (x1 * z2 - x2 * z1) % self.q != 0
			or (y1 * z2 - y2 * z1) % self.q != 0
		):
			return False

		return True

class CasperSigner(Ed25519):
	def __init__(self):
		super().__init__()

		self.current_path = os.path.dirname(os.path.abspath(__file__))
		parser = argparse.ArgumentParser()

		parser.add_argument(
			'args', 
			nargs = '*', 
			help = 'Positional arguments for specifying message, secret key, and public key - in that order.'
		)

		parser.add_argument(
			'-s', 
			action = 'store_true', 
			help = 'This flag instructs the signer to expect a SECP256K1 keypair instead of the default ED25519.'
		)

		args = parser.parse_args()
		self.all_args = args.args
		self.vid_type = 1
		self.secret_key_file = '/etc/casper/validator_keys/secret_key.pem'
		self.public_key_hex = ''
		self.__secret_key_b64string = ""
		self._public_key_b64string = ""
		self._secp_verifying_key = None
		self.asn1_signature = ""
		self.message = ""
		self.signature = None
		self.verified = False

	def show_help(self):
		bcolor = BColors()
		print("%sCasper Association%s Signer script -" % (bcolor.red2, bcolor.end))
		print("")
		print("This script is intended to produce signatures over the command line so that members can ")
		print("")
		print("This Signer Script takes 3 arguments:")
		print("\n %s* Argument 1 is the path to 'message.txt'%s to be signed. (required)" % (bcolor.green, bcolor.end))
		print("   This is downloaded from the Casper Association's member portal dashboard.")
		print("\n %s* Argument 2 is the path to your secret key%s." % (bcolor.green, bcolor.end))
		print("   This argument defaults to '/etc/casper/validator_keys/secret_key.pem'")
		print("\n %s* Argument 3 is your public key hex%s." % (bcolor.green, bcolor.end))
		print("   Otherwise known as your Validator ID.")
		print("   If your public key begins with a '01' byte, then")
		print("   it is a standard CasperLabs type ED25519 public key.")
		print("   If your public key begins with a '02' byte, then")
		print("   it is a CasperLabs type SECP256K1 public key.")
		print("   This script will automatically detect the correct case for your key.")
		print("")
		print("Example usage:")
		print("")
		print('  python3 sign.py  /path/to/message.txt  /path/to/secret_key.pem  VALIDATOR_ID')
		print('  python3 sign.py  ~/Downloads/message.txt  /etc/casper/validator_keys/secret_key.pem  011117189c666f81c5160cd610ee383dc9b2d0361f004934754d39752eedc64957')
		print('')

	def process_args(self):
		if len(self.all_args) == 0:
			self.show_help()
			sys.exit(0)

		if len(self.all_args) > 2:
			# message arg
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

			# secret key arg
			self.secret_key_file = self.all_args[1]
			if not os.path.isfile(self.secret_key_file):
				print("Could not find secret key '%s'" % self.secret_key_file)
				self.show_help()
				sys.exit(3)

			# public key arg
			self.public_key_hex = self.all_args[2]
			first_byte = self.public_key_hex[:2]
			if first_byte == '01':
				self.vid_type = 1
			elif first_byte == '02':
				self.vid_type = 2
			else:
				print("Invalid public key hex '%s'" % self.public_key_hex)
				self.show_help()
				sys.exit(4)

			self.public_key_hex = self.public_key_hex[2:]
		else:
			print("Missing arguments")
			self.show_help()
			sys.exit(5)

		return True

	def load_secret_key(self):
		self.__secret_key_b64string = ''

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
			secret_key_hex = secret_key_hex[-64:]
			secret_key_bytes = bytes.fromhex(secret_key_hex)

			self.signature = self.calculate_signature(
				bytes(self.message, 'utf8'),
				secret_key_bytes,
				bytes.fromhex(self.public_key_hex)
			).hex()

			self.asn1_signature = (
				"3046" + 
				"022100" + 
				self.signature[:64] + 
				"022100" + 
				self.signature[64:]
			)

		return self.signature

	def verify(self):
		if self.vid_type == 2:
			public_key_bytes = bytes.fromhex(self.public_key_hex)

			try:
				verifying_instance = ecdsa.VerifyingKey.from_string(
					public_key_bytes,
					curve = ecdsa.SECP256k1,
					hashfunc = hashlib.sha256
				)

				verifying_instance.verify(
					bytes.fromhex(self.signature),
					bytes(self.message, 'utf8')
				)
				self.verified = True
			except:
				self.verified = False
				print('\nPlease do not use this signature. We tested your signature using the public key specified and it did not pass. Check your file paths and hex keys you specified and try again.')
		else:
			public_key_bytes = bytes.fromhex(self.public_key_hex)

			try:
				self.verified = self.checkvalid(
					bytes.fromhex(self.signature),
					bytes(self.message, 'utf8'), 
					public_key_bytes
				)
			except:
				self.verified = False
				print('\nPlease do not use this signature. We tested your signature using the public key specified and it did not pass. Check your file paths and hex keys you specified and try again.')

		return self.verified


if __name__ == "__main__":
	bcolor = BColors()
	casigner = CasperSigner()
	casigner.process_args()
	casigner.load_secret_key()
	signature = casigner.sign()
	is_verified = casigner.verify()

	if casigner.vid_type == 2:
		signature = casigner.asn1_signature

	with open("%s/signature" % casigner.current_path, 'w') as write_signature:
		write_signature.write(signature)

	sig_type = 'SECP256k1' if casigner.vid_type == 2 else 'ED25519'
	highlight_color = bcolor.green if is_verified else bcolor.red

	print(
		"\n%s SIGNATURE: %s%s%s" % (
			sig_type,
			highlight_color,
			signature,
			bcolor.end
		)
	)

	if is_verified:
		print(
			"\nSIGNATURE %sVERIFIED%s" % (
				bcolor.green,
				bcolor.end
			)
		)
	else:
		print(
			"\nSIGNATURE %sNOT VERIFIED%s" % (
				bcolor.red,
				bcolor.end
			)
		)

	print(
		"\nYour signature file has been written to %s%s/signature%s." % (
			highlight_color, 
			casigner.current_path, 
			bcolor.end
		)
	)
	print("This is the file meant to be uploaded to the Casper Association Member portal.  If you are logged into a remote instance over SSH, you can simply copy/paste the %sraw hex string%s signature above to a plan text document (not richtext) on your local machine and use it for your signature upload." % (highlight_color, bcolor.end))
