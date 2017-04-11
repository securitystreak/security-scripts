<?php
require_once("classes/Template.php");
$t = new Template;
//$links = $t->getHeaderMenu();
echo "<ul>";
foreach($t->getHeaderMenu() as $text => $link){
	echo "<li><a href=".$link.">".$text."</a></li>";	
	}
echo "</ul>";
?>