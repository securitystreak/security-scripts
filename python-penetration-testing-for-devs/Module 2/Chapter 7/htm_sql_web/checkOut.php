<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<link href="style/php90.css" rel="stylesheet" type="text/css" />
<title>MyMobile Shop</title>
<script type="text/javascript">
function copyInfo(){
  var fullname;
  var email;
  var address;
    
  fullname = document.getElementById('fname').value;
  email = document.getElementById('email').value;
  address = document.getElementById('address').value;
  
  document.getElementById('sfname').value = fullname;
  document.getElementById('semail').value = email;
  document.getElementById('saddress').value = address;
}
</script>
</head>
<?php 
error_reporting(~E_NOTICE);
require_once("datastore.php");
require_once("classes/cart.php"); 
 
if($_POST['sub']){
 //billing
 $fullname = trim($_POST['fullname']);
 $email = trim($_POST['email']);
 $address = trim($_POST['address']);
 $city = trim($_POST['city']);
 $state = trim($_POST['state']);
 $country = trim($_POST['country']);
 $zipcode = trim($_POST['zipcode']);
 $phone = trim($_POST['phone']);
 //shipping
 $sfullname = trim($_POST['sfullname']);
 $semail = trim($_POST['semail']);
 $saddress = trim($_POST['saddress']);
 $scity = trim($_POST['scity']);
 $sstate = trim($_POST['sstate']);
 $scountry = trim($_POST['scountry']);
 $szipcode = trim($_POST['szipcode']);
 $sphone = trim($_POST['sphone']);
  $error = "";
 //validateion
 if(!$fullname){
   $error .="&nbsp;Please enter you full name<br>";

 }
 
 if(!$address){
    $error .="&nbsp;Please enter you address<br>";
 
 }
 if(!$email){
    $error .="&nbsp;Please enter your email<br>";
 
 }
 
 if(!$error){
 
  	$_SESSION['fullname'] = $fullname;
 	$_SESSION['email'] = $email;
 	$_SESSION['address'] = $address;
 	$_SESSION['city'] = $city;
 	$_SESSION['state'] = $state;
 	$_SESSION['country'] = $country;
 	$_SESSION['zipcode'] = $zipcode;
 	$_SESSION['phone'] = $phone;
	
	$_SESSION['sfullname'] = $sfullname;
 	$_SESSION['semail'] = $semail;
 	$_SESSION['saddress'] = $saddress;
 	$_SESSION['scity'] = $scity;
 	$_SESSION['sstate'] = $sstate;
 	$_SESSION['scountry'] = $scountry;
 	$_SESSION['szipcode'] = $szipcode;
 	$_SESSION['sphone'] = $sphone;
   
    header("Location: confirmCheckout.php");
	exit; 
 }
}
?>
<body>
<div id="header">Content for  id "header" Goes Here</div>
<div id="menu"><?php require_once("include/headerMenu.php");?></div>
<div id="bar"><?php require_once("bar.php");?></div>
	<div id="main">
	<h1>Checkout</h1>            	
                <form name="form1" method="post" action="checkOut.php" >               
                <table align="center" cellspacing="2" width="100%" >
                <tr>
                <td colspan="2"><em>Please Enter your Billing and Shipping Information.</em></td>                
                </tr>
                
                <?php if($error){ ?>
                <tr>
                <td colspan="2" style="padding:10px"><div style="background-color:#339999; width:400px; height:auto; color:#FFFFFF; border:1px solid #33FFCC; padding:5px;"><?php echo $error; ?></div></td>                
                </tr>
                <?php } ?>
                <tr>
                <td colspan="2" align="left"><strong>Billing Information</strong></td>                
                </tr>
                
                <tr>
                <td align="left">Full Name</td>
                <td align="left"><input type="text" name="fullname" id="fname" value="<?php echo $fullname; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">Email</td>
                <td align="left"><input type="text" name="email" id="email" value="<?php echo $email; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">Address</td>
                <td align="left"><input type="text" name="address" value="<?php echo $address; ?>" id="address" /></td>                
                </tr>
                
                <tr>
                <td align="left">City</td>
                <td align="left"><input type="text" name="city" value="<?php echo $city; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">State</td>
                <td align="left"><input type="text" name="state" value="<?php echo $state; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">Country</td>
                <td align="left"><input type="text" name="country" value="<?php echo $country; ?>" /></td>                
                </tr>
                
                
                <tr>
                <td align="left">Zip Code</td>
                <td align="left"><input type="text" name="zipcode" value="<?php echo $zipcode; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">Phone</td>
                <td align="left"><input type="text" name="phone" value="<?php echo $phone; ?>" /></td>                
                </tr>
                
                 <tr align="left">
                <td colspan="2"><strong>Shipping Information</strong><br />
                <input type="checkbox" name="same" value="1" onclick="copyInfo();" />&nbsp;Same as above</td>                
                </tr>
                
                <tr>
                <td align="left">Full Name</td>
                <td align="left"><input type="text" name="sfullname" id="sfname" value="<?php echo $sfullname; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">Email</td>
                <td align="left"><input type="text" name="semail" id="semail" value="<?php echo $semail; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">Address</td>
                <td align="left"><input type="text" name="saddress" id="saddress" value="<?php echo $saddress; ?>" /></td>                
                </tr>
                
                <tr>
                <td align="left">City</td>
                <td align="left"><input type="text" name="scity" value="<?php echo $scity; ?>" /></td>
                
                </tr>
                <tr>
                <td align="left">State</td>
                <td align="left"><input type="text" name="sstate" value="<?php echo $sstate; ?>" /></td>
                
                </tr>
                <tr>
                <td align="left">Country</td>
                <td align="left"><input type="text" name="scountry" value="<?php echo $scountry; ?>" /></td>
                
                </tr>
                
                
                <tr>
                <td align="left">Zip Code</td>
                <td align="left"><input type="text" name="szipcode" value="<?php echo $szipcode; ?>" /></td>
                
                </tr>
                
                <tr>
                <td align="left">Phone</td>
                <td align="left"><input type="text" name="sphone" value="<?php echo $sphone; ?>" /></td>
                
                </tr>
                <tr>
                <td></td>
                <td><input type="submit" name="sub" value="Confirm Order" />&nbsp;<input type="button" name="sub" value="Back" onclick="window.location='viewCart.php'" /></td>
                
                </tr>
                </table>
      </form>     
              
</div>
<!--</div>-->

</body>
</html>