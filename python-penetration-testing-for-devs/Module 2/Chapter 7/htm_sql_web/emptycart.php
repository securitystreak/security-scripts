<?php	
	include_once("classes/cart.php");

	if($_SESSION['cart'])
	{
		$_SESSION['cart'] = new Cart;
	}
	header("Location: viewCart.php");
	exit;
		
?>