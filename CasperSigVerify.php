<?php

include_once('vendor/autoload.php');
use \phpseclib3\Crypt\EC;
use \phpseclib3\Crypt\PublicKeyLoader;

class CasperSignature {
	/*
	@blockchainthomas

	* If CasperSignature->verify() returns true,
	then the signature is valid.

	* If CasperSignature->verify() returns false,
	then the signature is invalid.

	*/

	function __construct() {
		// Base ASN1 codes
		$sequence       = '30';
		$object_ident   = '06';
		$bit_string     = '03';
		$end_of_content = '00';

		// ed25519 OID
		$ed25519_bitstring_length = '21';
		$ed25519_identity         = '2b6570'; // 1.3.101.112

		// calculate ed25519 sequence
		$ed25519_identity_length = dechex(strlen($ed25519_identity) / 2);
		$ed25519_identity_length = strlen($ed25519_identity_length) % 2 == 0 ?
			$ed25519_identity_length :
			'0'.$ed25519_identity_length;

		$ed25519_sequence_length = dechex(
			2 + hexdec($ed25519_bitstring_length) +
			2 + hexdec($ed25519_identity_length)
		);

		$ed25519_sequence_length = strlen($ed25519_sequence_length) % 2 == 0 ?
			$ed25519_sequence_length :
			'0'.$ed25519_sequence_length;

		// sec256k1 OID
		$sec256k1_bitstring_length = '22';
		$sec256k1_identity         = '2b8104000a'; // 1.3.132.0.10

		// calculate sec256k1 sequence
		$sec256k1_identity_length = dechex(strlen($sec256k1_identity) / 2);
		$sec256k1_identity_length = strlen($sec256k1_identity_length) % 2 == 0 ?
			$sec256k1_identity_length :
			'0'.$sec256k1_identity_length;

		$sec256k1_sequence_length = dechex(
			2 + hexdec($sec256k1_bitstring_length) +
			2 + hexdec($sec256k1_identity_length)
		);

		$sec256k1_sequence_length = strlen($sec256k1_sequence_length) % 2 == 0 ?
			$sec256k1_sequence_length :
			'0'.$sec256k1_sequence_length;

		// build ed25519 leading ASN1 hex
		$this->ed25519_leading_hex =
			$sequence.
			$ed25519_sequence_length.
			$object_ident.
			$ed25519_identity_length.
			$ed25519_identity.
			$bit_string.
			$ed25519_bitstring_length.
			$end_of_content
		;

		// build sec256k1 leading ASN1 hex
		$this->secp256k1_leading_hex =
			$sequence.
			$sec256k1_sequence_length.
			$object_ident.
			$sec256k1_identity_length.
			$sec256k1_identity.
			$bit_string.
			$sec256k1_bitstring_length.
			$end_of_content
		;
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
			throw new Exception("\n\nCasperSignature->verify(signature, validator_id, message) requires 3 arguments:\n\n * 1. The signature as a hex string.\n\n * 2. The Validator Id as a hex string. Expecting 66 characters (33 bytes) represented by 32 bytes with a prepended '01' byte indicating ED25519 type, or 68 characters (34 bytes) represented by 33 bytes with a prepended '02' byte indicating SECP256K1 type.\n\n * 3. The original message that was signed by the user.\n\n");
		}

		if(
			strlen($validator_id) == 66
		) {
			$vid_type = $validator_id[0].$validator_id[1];
			$validator_id = substr($validator_id, 2);

			if($vid_type != '01')
				throw new Exception("Invalid validator_id length for ED25519 type. Should be 33 bytes.");
		} elseif(
			strlen($validator_id) == 68
		) {
			$vid_type = $validator_id[0].$validator_id[1];
			$validator_id = substr($validator_id, 2);

			if($vid_type != '02')
				throw new Exception("Invalid validator_id length for SECP256K1 type. Should be 34 bytes.");
		} else {
			throw new Exception("validator_id must be either 66 or 68 characters long.");
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
				$this->ed25519_leading_hex.
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
				$bytes_signature = hex2bin(trim($signature));
			} catch(Exception $e) {
				throw new Exception("Invalid signature hex string");
			}

			try {
				$signature_is_valid = $public_key_instance->verify(
					$message,
					$bytes_signature
				);
			} catch(Exception $e) {
				$signature_is_valid = false;
			}

			if($signature_is_valid) {
				return true;
			}

			return false;

		} else {
			// SECP256K1 SIGNATURE VERIFICATION
			$public_key = (
				$this->secp256k1_leading_hex.
				$validator_id
			);

			$base64_public_key = base64_encode(
				hex2bin($public_key)
			);

			if(strlen($base64_public_key) > 64) {
				$pemformat = (
					"-----BEGIN PUBLIC KEY-----\n".
					substr($base64_public_key, 0, 64)."\n".
					substr($base64_public_key, 64).
					"\n-----END PUBLIC KEY-----\n"
				);
			} else {
				$pemformat = (
					"-----BEGIN PUBLIC KEY-----\n".
					$base64_public_key.
					"\n-----END PUBLIC KEY-----\n"
				);
			}

			try {
				$public_key_instance = PublicKeyLoader::load(
					$pemformat,
					$password = false
				)->withHash('sha256');
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
		}
	}
}

?>