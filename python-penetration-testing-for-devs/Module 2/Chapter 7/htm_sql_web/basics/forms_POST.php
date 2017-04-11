<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>

<body>
<?php
if (isset($_REQUEST['submit'])){  
         echo "Hi ".$_REQUEST['name']."!<br />";
         echo "The address ".$_REQUEST['email']." has  subscribed for new letter<br />"; 	  
		 }

 ?>
        <form action="<?php $_SERVER['SCRIPT_NAME'] ?>" method="post">
        <p>Name:<br />
        <input type="text" name="name" size="20" maxlength="40" value="" /> </p>
        <p>Email Address:<br />
        <input type="text" name="email" size="20" maxlength="40" value="" /></p>
        <input type="submit" name = "submit" value="Go!" />
        </form>
 

</body>
</html>