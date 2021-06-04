<?php

include_once(dirname(__FILE__).'/../CasperSigVerify.php');
use \phpseclib3\Crypt\EC;
use \phpseclib3\Crypt\PublicKeyLoader;

if(
	isset($argv) &&
	isset($argv[1]) &&
	$argv[1] == '-s'
) {
	$my_validator_id = file_get_contents(
		dirname(__FILE__).
		'/secp256k1.public.hex'
	);
} else {
	$my_validator_id = file_get_contents(
		dirname(__FILE__).
		'/test.public.hex'
	);
}

$my_signature = file_get_contents(dirname(__FILE__).'/../signature');
$my_message = 'hello';

$c = new CasperSignature();
$sig = $c->verify(
	$my_signature,
	$my_validator_id,
	$my_message
);

echo "\n".($sig ? 'GOOD SIGNATURE' : 'BAD SIGNATURE');
echo "\n";
