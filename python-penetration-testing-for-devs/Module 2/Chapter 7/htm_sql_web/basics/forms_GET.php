<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>

<body>
<?php
if(isset($_GET['submit'])){
	echo "Welcome ".$_GET["fname"]."<br />";
    echo "You are ". $_GET["age"] ." years old!"; 
}
 ?>
<form action="forms_GET.php" method="get">
       Name: <input type="text" name="fname" />  
	   Age: <input type="text" name="age" />
	   <input type="submit" name = "submit" value="Go!" />
</form> 
</body>
</html>
