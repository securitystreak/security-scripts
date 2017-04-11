<?php

$host='localhost';
$username='user';
$password='password';
$db_name="data";
$tbl_name="data";

$comment = $_REQUEST['comment'];

mysql_connect($host, $username, $password) or die("Cannot contact server");
mysql_select_db($db_name)or die("Cannot find DB");

$sql="INSERT INTO $tbl_name VALUES('$comment')";

$result=mysql_query($sql);

mysql_close();
?>