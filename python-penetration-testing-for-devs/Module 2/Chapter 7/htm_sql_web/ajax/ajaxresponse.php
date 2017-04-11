<?php
error_reporting(~E_NOTICE);   
 //Class object creation
 require_once("../datastore.php");
 $id = $_GET['id']; echo "Value of Cat_id=".$id;
 
 $prodsql = "SELECT a.name as cat_name, b.name as prod_name, b.description as prod_desc,"
           ." b.price as prod_price, b.image as prod_img"
		   ." FROM categories a INNER JOIN products b"
		   ." WHERE a.id = b.cat_id AND b.cat_id=$id";
		   
$prodres = mysql_query($prodsql);
$numrow = mysql_num_rows($prodres); //echo $numrow;
echo "<table border=\"2\">";
while($prodrow = mysql_fetch_array($prodres))
{
	echo $str = "<tr><td>".$prodrow['cat_name'] ."</td><td>".$prodrow['prod_name'] ."</td><td>".$prodrow['prod_desc']."</td><td>".$prodrow['prod_price']."</td></tr>"; 
	}
echo "</table>";

?>