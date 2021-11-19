# Casper Validator Signer/Verifier

### For the Casper Association

## Description

Contains a python3 script that generates a signature in hex string format from a validator's keys for the purpose of providing proof of ownership of a node to the Casper Association. Also contains a PHP class that is to be implemented by the Casper Association Portal for instant verification of a given node's signature.

## Requirements

* Python 3.7+
* ed25519 python package
* ecdsa python package

## Setup

```bash
git clone https://github.com/ledgerleapllc/caspersignerverifier
cd caspersignerverifier/
python3 sign.py
```

If you want to run PHP based test suite, you will need to install those dependencies also.

```bash
composer install
```

## Testing

*test/* contains full test results and data that can be used to implement. The test key files, *test.secret.key*, *test.public.key*, *test.public.hex*, were generated using ***casper-client*** on a Casper node on 06/03/2021. Other methods have been used to generate keys, such as PHP generated ED25519 pairs, and python generated ED25519 pairs, and they seem to work. But we do not want to guarantee their stable support at this time.

```bash
python3 sign.py 'hello' test/test.secret.key test/test.public.key
php test/test.php
```

Or use the pre-packaged all-in-one testing script.

```bash
sudo su $USER test/test.sh
```

## Usage

For most users, the following process should be followed:

Download a message file to be signed. It will contain a brief message and a timestamp. The message will be downloaded to the user's downloads folder.

```bash
python3 sign.py ~/Downloads/message.txt path/to/secret.key path/to/public.key
```

You should see something like:

	SIGNATURE:
	19ad9719cb3f3...
	GOOD SIGNATURE

This output is producing the signature in the command line that can be copy/paste into a web form input. It is also outputting the signature to a file in the same directory as 'sign.py' named 'signature' for uploading. Either text input or file upload can be used for verification. But file upload method is most likely going to be implemented over copy/paste into form input.

## SECP256k1 Support

SECP256k1 is now supported. The test keys used were generated using the ***casper-client*** on a Casper node on 06/04/2021. Pass the flag -s in python to specify, like:

```bash
python3 sign.py -s
```

For the included signature testing script, pass the same flag into PHP, like:

```bash
php test/test.php -s
```

## Contact

**thomas@ledgerleap.com**

**@blockchainthomas**