<?php
 $q = $_GET['q']; 
 if($q=='a'){ 
  $result = "Ali, Ahmad, Ahsan, Alpha"; 
 }elseif($q=='b'){ 
  $result = "Babar, Bravo";
 }elseif($q=='c'){ 
  $result = "charlie";
 }else{
 	$result = "No Suggestion";  
 } 
 echo $result;
?>