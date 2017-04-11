<?php
 require_once("datastore.php");
 require_once("classes/Cart.php"); 
 //$cart = "";
 $cart	=	$_SESSION['cart'];
  print_r($cart);
 echo "<br />";
 ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<link href="style/php90.css" rel="stylesheet" type="text/css" />
<title>MyMobile Shop</title>
<script type="text/javascript">
function confRem(){	
	if(confirm("Are you sure to remove this item from cart")){
		return true;
	}	
	return false;
}
</script>
</head>

<body>
<div id="header">Content for  id "header" Goes Here</div>
<div id="menu"><?php require_once("include/headerMenu.php");?></div>
<div id="bar"><?php require_once("bar.php");?></div>
	<div id="main">
	<h1>Shopping Cart</h1>
            	<p>                
                <table align="center" style="border:1px solid black; border-collapse:collapse;" cellpadding="2" cellspacing="2" width="100%" >
                <tr>
                <th>#</th>
                <th>Product</th>
                <th>Price</th>
                <th>Qty</th>
                <th>Total</th>
                <th>Option</th>                
                </tr>
                <form name="form1" method="post" action="updateBasket.php">               
                <?php 
				if(count($cart->items)>0){				
					for($i = 0; $i<count($cart->items); $i++){ ?>
                	<input type="text" name="itemids[]" value="<?php echo $cart->items[$i][0];?>" />
                	<tr>                
                		<td><?php echo $cart->items[$i][0];  ?></td>
                		<td><img src="Products/<?php echo $cart->items[$i][3];?>" height="100px" width="100px" /><br /><?php echo $cart->items[$i][1];  ?></td>
                		<td>$<?php echo $cart->items[$i][2];  ?></td>                
                		<td><input type="text" name="items[]" value="<?php echo $cart->items[$i][4];?>" size="2"/></td>
                		<td><?php echo $cart->items[$i][5];  ?></td>
                		<td><a href="removeItem.php?itemid=<?php echo $cart->items[$i][0]; ?>" class="a" onclick="return confRem();">Remove this Item</a></td>                
                	</tr>                
                <?php } 
				}else{
				?>
                	<tr><td colspan="6" align="center">&nbsp;</td></tr>
                	<tr><td colspan="6" align="center"><?php  echo "Shopping cart empty!!!";  } ?></td></tr>
                 	<tr><td colspan="6">&nbsp;</td></tr>
                  	<tr><td colspan="6" align="right"><strong>Total:</strong> $<?php echo  $cart->calculate_gTotal(); ?></td></tr>
                    <tr><td colspan="6">&nbsp;</td></tr>
                	<tr><td colspan="6" align="center"> 
                	<input type="submit" name="update" value="Update Cart" />
                 	<input type="button" name="emptycart" value="Empty Cart" onclick="window.location='emptycart.php'" />&nbsp;<input type="button" name="continue" value="Continue Shopping" onclick="window.location='index.php'" />&nbsp;<input type="button" name="checkout" value="Checkout" onclick="window.location='checkOut.php'" /></td></tr>
                	</form>
                	</table>                
                </p>
    
    </div>
<!--</div>-->

</body>
</html>