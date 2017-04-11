<?php
require("config.php");
$conn = mysql_connect($dbhost,$dbusername,$dbpassword);
mysql_select_db($dbdatabase,$conn) or die("Cannot select database");
?>