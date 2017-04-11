<?php
	include_once("classes/Cart.php");	 	
	$id     = 0;
	$title  = "";
	$price  = 0.0;
	$img    = "";
	$qty = 0;
	
	$cart	=	$_SESSION['cart'];
	print_r($cart);
		
	if($_POST['sub']){

		echo $id    = intval($_POST['id']);
		echo $title  = $_POST['name'];;
		echo $price = $_POST['price'];
		echo $img   = $_POST['image'];
		echo $qty= 1;
	 		//exit;
		$cart->add_item($id, $title, $price, $img, $qty);
			
		header("Location: viewCart.php");
		exit;

	 }
	 
	 
?>