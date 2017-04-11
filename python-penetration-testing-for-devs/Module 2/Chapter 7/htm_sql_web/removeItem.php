<?php
	require_once("classes/cart.php");
	session_start();
	$cart = $_SESSION['cart'];	
	$_itemid = intval($_REQUEST['itemid']);	
	
	if(!$_itemid){
		header("Location: viewCart.php");
		exit;
	}
	
	$result = $cart->remove_item($_itemid);		
		header("Location: viewCart.php");
	exit;
	

?>