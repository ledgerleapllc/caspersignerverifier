<?php

include_once('vendor/autoload.php');
use \phpseclib3\Crypt\EC;
use \phpseclib3\Crypt\PublicKeyLoader;

class CasperSignature {
	/*

	* If CasperSignature->verify() returns false,
	then the signature is invalid.

	* If CasperSignature->verify() returns false,
	then the signature is invalid.

	*/

	function __construct() {
		$this->leading_hex_casperclient = '302a300506032b6570032100';
		$this->leading_hex_phpseclib3 = '302c300706032b65700500032100';
	}

	function __destruct() {}

	function verify(
		$signature = null,
		$validator_id = null,
		$message = null
	) {
		if(
			!$signature ||
			!$validator_id ||
			!$message
		) {
			throw new Exception("\n\nCasperSignature->verify(sig, vid, msg) requires 3 arguments:\n\n * 1. The signature as a hex string.\n\n * 2. The Validator Id as a hex string. Expecting 66 characters (33 bytes) which would represent 32 bytes with either '01' or '02' byte at the beginning indicating ED25519 type, or SECP256K1 type, respectively.\n\n * 3. The original message that was signed by the user.\n\n");
		}

		if(
			strlen($validator_id) == 66
		) {
			$vid_type = $validator_id[0].$validator_id[1];
			$validator_id = substr($validator_id, 2);
		} elseif(
			strlen($validator_id) == 64
		) {
			$vid_type = '01';
		} else {
			throw new Exception("validator_id must be either 64 or 66 characters long.");
		}

		if(
			$vid_type != '01' &&
			$vid_type != '02'
		) {
			throw new Exception("The first byte of a validator_id must be either '01' indicating an ED25519 key, or '02' indicating a SECP256K1 key.");
		}

		if($vid_type == '01') {
			// ED25519 SIGNATURE VERIFICATION

			$public_key = (
				$this->leading_hex_casperclient.
				$validator_id
			);

			$base64_public_key = base64_encode(
				hex2bin($public_key)
			);

			$pemformat = (
				"-----BEGIN PUBLIC KEY-----\n".
				$base64_public_key.
				"\n-----END PUBLIC KEY-----\n"
			);

			try {
				$public_key_instance = PublicKeyLoader::load(
					$pemformat,
					$password = false
				);
			} catch(Exception $e) {
				throw new Exception("Could not read user's public key\n\n".$e);
			}

			try {
				$bytes_signature = hex2bin($signature);
			} catch(Exception $e) {
				throw new Exception("Invalid signature hex string");
			}

			try {
				$signature_is_valid = $public_key_instance->verify(
					$message,
					$bytes_signature
				);
			} catch(Exception $e) {
				throw new Exception("Invalid signature hex string\n\n".$e);
			}

			if($signature_is_valid) {
				return true;
			}

			return false;

		} else {
			// SECP256K1 SIGNATURE VERIFICATION
			throw new Exception("Our Validator Signature Verifier does not support SECP256K1 key signatures yet. 06/03/2021");
		}
	}
}

?>