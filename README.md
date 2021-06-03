# Casper Validator Signer/Verifier

### For the Casper Association

## Description

Contains a python3 script that generates a signature in hexidecimal format from a validator's keys for the purpose of providing proof of ownership of a node to the Casper Association. Also contains a PHP class that is to be implemented by the Casper Association Portal for instant verification of a given node's signature.

## Setup

	$ git clone https://github.com/ledgerleapllc/caspersignerverifier
	$ cd caspersignerverifier/
	$ composer install

## Testing

*test/* contains full test results and data that can be used to implement. The test key files, *test.secret.key*, *test.public.key*, *test.public.hex*, were generated using ***casper-client*** on a Casper node on 06/03/2021. Other methods have been used to generate keys, such as PHP generated ED25519 pairs, and python generated ED25519 pairs, and they seem to work. But we do not want to guarantee their stable support at this time. We will also be adding SEKP256k1 keypair support soon.

	$ python3 sign.py 'hello' test/test.secret.key test/test.public.key
	$ php test/test.php

## Contact

**thomas@ledgerleap.com**

**@blockchainthomas**