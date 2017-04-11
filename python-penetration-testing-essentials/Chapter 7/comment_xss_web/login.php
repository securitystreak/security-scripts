<?php 
session_start();
include_once("connect.php") 
           
?>
<?php

$uname = $_POST['user'];
$pass =  $_POST['pass'];

$sql = "SELECT count(*) FROM users where (
user='".$uname."' and pass='".$pass."')";

$qury = mysql_query($sql);
$result = mysql_fetch_array($qury);

if($result[0]>0)
{
if($uname =="admin")
{
 $_SESSION['userName'] = 'admin';

header("location: admin.php");
//echo"<br /><a href='logout.php'>LOGOUT</a>";
}

else
{
$_SESSION['userName'] = $uname;
header("location: home.php");
}
}
else
{
echo "Login Failed";
}
?>
