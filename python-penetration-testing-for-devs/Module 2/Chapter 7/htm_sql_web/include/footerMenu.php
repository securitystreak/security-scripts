<?php
require_once("classes/Template.php");
$t = new Template;
$links = $t->getFooterMenu();
echo "<ul>";
foreach($links as $text => $link){
	echo "<li><a href=".$link.">".$text."</a></li>";	
	}
echo "</ul>";
?>