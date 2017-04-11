<?php
require_once("classes/Template.php");
$t = new Template;
$links = $t->getadds();
echo "<table>";
foreach($links as $text => $link){
	echo "<tr><td></td></tr>";
	echo "<tr><td><a href=\"adds/".$link."\" target=\"_blank\"><img src=\"adds/".$text."\" /></a></td></tr>";
	echo "<tr><td></td></tr>";	
	}
echo "</table>";
?>