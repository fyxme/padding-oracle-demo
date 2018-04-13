<?php

// https://secure.php.net/manual/en/function.mcrypt-create-iv.php#114645

include 'tools.php';

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

$num_chars = 8;//number of characters for captcha image

$captcha_text = get_captcha_text($num_chars);
$imagedata = get_captcha_image($captcha_text);

$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$iv = mcrypt_create_iv($iv_size, MCRYPT_DEV_RANDOM);

// cipher verification
$cv = base64_encode($iv.aes128_cbc_encrypt($encryption_key, $captcha_text, $iv));

?>
<!DOCTYPE html>
<html lang="en">
    <head>
		<meta name="viewport" content="width=device-width, initial-scale=1">

		<!-- Website CSS style -->
		<link href="css/bootstrap.min.css" rel="stylesheet">

		<!-- Website Font style -->
	    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.6.1/css/font-awesome.min.css">
		<link rel="stylesheet" href="css/main.css">
		<!-- Google Fonts -->
		<link href='https://fonts.googleapis.com/css?family=Passion+One' rel='stylesheet' type='text/css'>
		<link href='https://fonts.googleapis.com/css?family=Oxygen' rel='stylesheet' type='text/css'>

		<title>Admin</title>
        <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
        <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.0/js/bootstrap.min.js"></script>
        <script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
	</head>
	<body>
		<div class="container">
			<div class="row main">
				<div class="main-login main-center">
                <div style="text-align:center">
                    <img src="img/lock.png" alt="" width="100px">
                </div>
                <h1 style="color:white;text-align:center">Welcome to <u>Supasecure</u> Voting System</h1><br>
				<h4>Please fill in the form to access the voting page</h4>
					<form class="" method="get" action="verify-captcha.php">
						<div class="form-group">
							<label for="name" class="cols-sm-2 control-label">Your Full Name</label>
							<div class="cols-sm-10">
								<div class="input-group">
									<span class="input-group-addon"><i class="fa fa-user fa" aria-hidden="true"></i></span>
									<input type="text" class="form-control" name="name" id="name"  placeholder="Enter your Name"/>
								</div>
							</div>
						</div>

						<div class="form-group">
							<label for="email" class="cols-sm-2 control-label">Your Email</label>
							<div class="cols-sm-10">
								<div class="input-group">
									<span class="input-group-addon"><i class="fa fa-envelope fa" aria-hidden="true"></i></span>
									<input type="text" class="form-control" name="email" id="email"  placeholder="Enter your Email"/>
								</div>
							</div>
						</div>

                        <div class="form-group">
                            <label for="email" class="cols-sm-2 control-label">Verification code</label>
                            <p>To make sure you're not a robot, please enter the verification code below</p>
                            <div class="text-center" style="margin-bottom:5px">
                                <!-- DEBUG: [Remove before launching webiste] To test captcha codes use this route : /test-catpcha.php with parameters "captcha-attempt" and "captcha-verification" -->
                                <img id="captcha-img" src="data:image/png;base64,<?php echo base64_encode($imagedata)?>">
                                <input id="captcha-verification" type="hidden" name="captcha-verification" value="<?php echo $cv?>">
                            </div>

                            <div class="cols-sm-10">
                                <div class="input-group">
                                    <span class="input-group-addon"><i class="fa fa-lock fa" aria-hidden="true"></i></span>
                                    <input type="text" class="form-control" name="captcha-attempt" id="email"  placeholder="Verification Code"/>
                                </div>
                            </div>
                        </div>


						<div class="form-group ">
                            <input id="button" class="btn btn-primary btn-lg btn-block login-button" type="submit" type="button" name="" value="Register to vote">
						</div>

					</form>
				</div>
			</div>
		</div>

		 <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="js/bootstrap.min.js"></script>
	</body>
</html>
