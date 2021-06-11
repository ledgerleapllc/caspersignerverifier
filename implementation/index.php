<?php

include_once(dirname(__FILE__).'/../CasperSigVerify.php');

$timestamp = date('m/d/Y');
$message = "Please use the Casper Signature python tool to sign this message! ".$timestamp;
$public_validator_key = "01bee8817a99d8a1cf23434c5b25a90dba00947d2d4a0a827aa1eca60da0ee22b8";
$signature = $_REQUEST['signature'] ?? null;

if($signature) {
	$CasperSigner = new CasperSignature();

	$verified = $CasperSigner->verify(
		$signature,
		$public_validator_key,
		$message
	);

	exit($verified ? "Verified!" : "Failed verification");
}

$file = $_FILES['signature-file'] ?? null;

if($file) {
	$name = $file['name'] ?? null;
	$tmp_name = $file['tmp_name'] ?? null;

	if(
		$tmp_name &&
		$name == 'signature'
	) {
		$CasperSigner = new CasperSignature();

		try {
			$hexstring = file_get_contents($tmp_name);
		} catch(exception $e) {
			$hexstring = '';
		}

		$verified = $CasperSigner->verify(
			trim($hexstring),
			$public_validator_key,
			$message
		);

		header(
			'location:http://'.
			$_SERVER['HTTP_HOST'].
			$_SERVER['REQUEST_URI'].'?'.(
				$verified ? 'verified' : 'failed'
			)
		);
		exit();
	}
}

?>
<!DOCTYPE html>
<html>
<head>
	<title>Demo Implementation</title>
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@3.4.1/dist/css/bootstrap.min.css" integrity="undefined" crossorigin="anonymous">
</head>
<body>
	<div class="container">
		<div class="row">
			<div class="col-md-12">
				<h1 class="text-center">Demo Implementation</h1>
			</div>
		</div>
		<div class="row">
			<div class="col-md-6 text-center">
				<h2>Download Message</h2>
				<p>Once you download the message file, please use the Casper Signature python tool to sign it. Using "<b>$ python3 sign.py ~/Downloads/message.txt test/test.secret.key test/test.public.key</b>"</p>
				<button class="btn btn-primary" id="download-btn">Download</button>
			</div>
			<div class="col-md-6 text-center">
				<h2>Get Verified</h2>
				<h3>Using this form</h3>
				<input type="text" name="signature" id="signature-input" style="width: 100%; display: block; margin-bottom: 15px; padding: 6px;" placeholder="Enter your signarure hash here">
				<button class="btn btn-primary" id="verify-btn1">Verify Me</button>

				<br><br><br>

				<h3>Using file upload</h3>
				<form action="<?php echo 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']; ?>" method='post' enctype="multipart/form-data">
				<input style="width: 100%; display: block; margin-bottom: 15px; padding: 6px;" type="file" name="signature-file" id="signature-file">
				<button type="submit" class="btn btn-primary" id="verify-btn2">Verify Me</button>
			</div>
		</div>
	</div>

	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script>
		var message = "<?php echo $message; ?>";

		$("#download-btn").click(function() {
			download_file(message, 'message.txt');
		});

		function download_file(messageFile, filename) {
			var blob = new Blob(
				[messageFile], {
					type: 'text/csv;charset=utf-8;' 
				}
			);

			if (navigator.msSaveBlob) { // IE 10+
				navigator.msSaveBlob(blob, filename);
			} else {
				var link = document.createElement("a");

				if (link.download !== undefined) {
					var url = URL.createObjectURL(blob);
					link.setAttribute("href", url);
					link.setAttribute("download", filename);
					link.style.visibility = 'hidden';
					document.body.appendChild(link);
					link.click();
					document.body.removeChild(link);
				}
			}
		}

		$("#verify-btn1").click(function() {
			var hash = $("#signature-input").val();
			// console.log(hash);

			if(hash && hash != '') {
				$.ajax({
					url: window.location.href,
					method: 'post',
					data: {
						signature: hash
					}
				})
				.done(function(res) {
					console.log(res);
					alert(res);
				});
			}
		});

		if(
			<?php echo isset($_GET['verified']) ? 'true' : 'false'; ?>
		) {
			alert('Verified!');
			window.location.href = window.location.protocol + '//' + window.location.host + window.location.pathname;
		}

		if(
			<?php echo isset($_GET['failed']) ? 'true' : 'false'; ?>
		) {
			alert('Failed');
			window.location.href = window.location.protocol + '//' + window.location.host + window.location.pathname;
		}

	</script>
</body>
</html>