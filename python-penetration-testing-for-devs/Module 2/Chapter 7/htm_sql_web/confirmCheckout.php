<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<link href="style/php90.css" rel="stylesheet" type="text/css" />
<title>MyMobile Shop</title>
</head>
<?php
error_reporting(~E_NOTICE);
require_once("datastore.php");
include_once("classes/cart.php"); 
$cart	=	$_SESSION['cart'];
//print_r($dataArray);
if($_POST['sub']){
    $fullname = $_SESSION['fullname'] ;
    $email    = $_SESSION['email'];
 	$address  = $_SESSION['address'];
 	$city     = $_SESSION['city'] ;
 	$state    = $_SESSION['state'];
 	$country  = $_SESSION['country'];
 	$zipcode  = $_SESSION['zipcode'];
 	$phone    = $_SESSION['phone'] ;
	
	$sfullname = $_SESSION['sfullname'] ;
    $semail    = $_SESSION['semail'];
 	$saddress  = $_SESSION['saddress'];
 	$scity     = $_SESSION['scity'] ;
 	$sstate    = $_SESSION['sstate'];
 	$scountry  = $_SESSION['scountry'];
 	$szipcode  = $_SESSION['szipcode'];
 	$sphone    = $_SESSION['sphone'] ;
    
	$gtotal = $cart->calculate_gTotal();
	$tQty    = $cart->calculate_qty();
	
	 $sql = "INSERT INTO orders ( orderStatus ,OrderTotal ,orderTotalQty , Orderdate ,Fname ,
	 Email , Address ,Country ,City ,State ,Zip ,Phone ,sFname ,sEmail ,sAddress ,sCountry ,sCity ,sState ,
     sZip , sPhone) values(\"t\", $gtotal ,$tQty, now(),
	 \"$fullname\", \"$email\",\"$address\",\"$country\", \"$city\",\"$state\",\"$zipcode\", \"$phone\",
	 \"$sfullname\", \"$semail\",\"$saddress\",\"$scountry\", \"$scity\",\"$sstate\",\"$szipcode\", \"$sphone\")" ;  
	
	
	if(mysql_query($sql)){
	   
	  $maxid = mysql_insert_id();echo $maxid;
	  	  
	  for($i = 0; $i<count($cart->items); $i++){
	   $pid = $cart->items[$i][0];
	   $qty  = $cart->items[$i][4];
	   $price = $cart->items[$i][2];
	   $total = $cart->items[$i][5];
	  
	    $itemsSql = "INSERT INTO orderitems set Orders_id= $maxid , Products_id= $pid , quantity= $qty ,
	    price =$price, total= $total ";
         if(mysql_query($itemsSql)){
		 
		  //echo "Data recorderd sucessfully";
		 
		 }
	  }
	  $str= '<form action="https://www.paypal.com/cgi-bin/webscr" method="post" name="form1" id="form1">
				<input type="text" name="cmd" value="_cart">
				<input type="text" name="upload" value="1">
				<input type="text" name="business" value="sales@mymobileshop.com">';
				$str .="<input type='text' name='invoice' value='$maxid'>";
				
				$j=1;
			
			for ($i=0; $i<count($cart->items); $i++){		 			 		
		 				 
				$_itemtitle    = $cart->items[$i][1];
		 		$_itemPrice    = $cart->items[$i][2];		 		
		 		$_quantity     = $cart->items[$i][4];
				
					
				$str .= "<input type='text' name='item_name_$j' value='$_itemtitle'>
				<input type='text' name='amount_$j' value='$_itemPrice'>
		 		<input type='text' name='quantity_$j' value='$_quantity'>";
				$j++;
		}
	  $str .= '<input type="text" name="currency_code" value="USD">
			<input type="text" name="return" value="http://www.mymobileshop.com/paypall_ret.php">
			<input type="text" name="rm" value="2">
			<input type="text" name="cancel_return" value="http://www.mymobileshop.com/cancelReturn.php">
			<input type="text" name="notify_url"  value="http://www.mymobileshop.com/paypallReturn.php">
			<input type="image" src="https://www.paypal.com/en_US/i/btn/x-click-butcc.gif"
	       	border="0" name="submit" alt="Make payment - it is fast, free and secure!">
			</form>';
	echo $str;
	
			echo '<script language="javascript">document.form1.submit();</script>';
      	  
	
	}else{
	
	 echo "Error in query";
	}
 
 }
 
?>
<body>
<div id="header">Content for  id "header" Goes Here</div>
<div id="menu"><?php require_once("include/headerMenu.php");?></div>
<div id="bar"><?php require_once("bar.php");?></div>
	<div id="main">
    <h1>Confirm Order</h1>                
                <form name="form1" method="post" action="confirmCheckout.php" >
                <table align="center" style="border:1px solid black; border-collapse:collapse;" cellpadding="2" cellspacing="2" width="100%" >
                <tr>
                <th>#</th>
                <th>Product</th>
                <th>Price</th>
                <th>Qty</th>
                <th>Total</th>
                
                
                </tr>
              
               
                <?php 
				if(count($cart->items)>0){
				
				for($i = 0; $i<count($cart->items); $i++){ ?>
                <input type="hidden" name="itemids[]" value="<?php echo $cart->items[$i][0];?>" />
                <tr>
                
                <td>
				
				<?php echo $cart->items[$i][0];  ?></td>
                <td><img src="Products/<?php echo $cart->items[$i][3];  ?>" height="100px" width="100px" /><br /><?php echo $cart->items[$i][1];  ?></td>
                <td>$<?php echo $cart->items[$i][2];  ?></td>
                
                <td><?php echo $cart->items[$i][4]; ?></td>
                <td><?php echo $cart->items[$i][5];  ?></td>
                
                </tr>
                
                <?php } 
				}
				else 
				   {
				?>
                <tr><td colspan="6" align="center">&nbsp;</td></tr>
                <tr><td colspan="6" align="center"><?php  echo "Shopping cart empty!!!";  } ?></td></tr>

                 <tr><td colspan="6">&nbsp;</td></tr>
                  <tr><td colspan="6" align="right"><strong>Grand Total:</strong> $<?php echo  $cart->calculate_gTotal(); ?></td></tr>
                   <tr><td colspan="6">&nbsp;</td></tr>
                <tr><td colspan="6" align="center"> 
               
                </table>
                <table align="center" cellspacing="2" width="100%">
                <tr>
                <td colspan="2"><em>Please review your order details and confirm order.</em></td>
                
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
                <td align="left"><?php echo $_SESSION['fullname'] ; ?></td>
                
                </tr>
                
                <tr>
                <td align="left">Email</td>
                <td align="left"><?php echo $_SESSION['email']; ?></td>
                </tr>
                
                <tr>
                <td align="left">Address</td>
                <td align="left"><?php echo $_SESSION['address']; ?></td>
                
                </tr>
                
                <tr>
                <td align="left">City</td>
                <td align="left"><?php echo $_SESSION['city'] ?></td>
                
                </tr>
                <tr>
                <td align="left">State</td>
                <td align="left"><?php echo $_SESSION['state']; ?></td>
                
                </tr>
                <tr>
                <td align="left">Country</td>
                <td align="left"><?php echo $_SESSION['country']; ?></td>
                
                </tr>
                
                
                <tr>
                <td align="left">Zip Code</td>
                <td align="left"><?php echo $_SESSION['zipcode']; ?></td>
                
                </tr>
                
                <tr>
                <td align="left">Phone</td>
                <td align="left"><?php echo $_SESSION['phone']; ?></td>
                
                </tr>
                
                 <tr>
                <td colspan="2" align="left"><strong>Shipping Information</strong><br />
                <tr>
                <td align="left">Full Name</td>
                <td align="left"><?php echo $_SESSION['sfullname'] ; ?></td>
                
                </tr>
                
                <tr>
                <td align="left">Email</td>
                <td align="left"><?php echo $_SESSION['semail']; ?></td>
                </tr>
                
                <tr>
                <td align="left">Address</td>
                <td align="left"><?php echo $_SESSION['saddress']; ?></td>
                
                </tr>
                
                <tr>
                <td align="left">City</td>
                <td align="left"><?php echo $_SESSION['scity'] ?></td>
                
                </tr>
                <tr>
                <td align="left">State</td>
                <td align="left"><?php echo $_SESSION['sstate']; ?></td>
                
                </tr>
                <tr>
                <td align="left">Country</td>
                <td align="left"><?php echo $_SESSION['scountry']; ?></td>
                
                </tr>
                
                
                <tr>
                <td align="left">Zip Code</td>
                <td align="left"><?php echo $_SESSION['szipcode']; ?></td>
                
                </tr>
                
                <tr>
                <td align="left">Phone</td>
                <td align="left"><?php echo $_SESSION['sphone']; ?></td>
                
                </tr>
                 <tr>
                <td align="left"></td>
                <td align="left"><input type="submit" name="sub" value="Confirm Order" /></td>
                
                </tr>
                 </table>
                </form>               
    </div>
<!--</div>-->

</body>
</html>