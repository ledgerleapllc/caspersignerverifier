<?php

include_once(dirname(__FILE__).'/../CasperSigVerify.php');

$my_validator_id = file_get_contents(dirname(__FILE__).'/test.public.hex');
$my_signature = file_get_contents(dirname(__FILE__).'/../signature');
$my_message = 'hello';

$c = new CasperSignature();
$sig = $c->verify(
	$my_signature,
	$my_validator_id,
	$my_message
);

echo $sig ? 'GOOD SIGNATURE' : 'BAD SIGNATURE';

