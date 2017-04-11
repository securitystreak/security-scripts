<?php

 require_once("../datastore.php");
 $pid = intval($_GET['pid']);
 //echo $pid;
 if($pid >0){
    mysql_query("DELETE from products WHERE id = $pid");
    header("Location: viewProducts.php?flag=1");
	exit;
	
 }



?>