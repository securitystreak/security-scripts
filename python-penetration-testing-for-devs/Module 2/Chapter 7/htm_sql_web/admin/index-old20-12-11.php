<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>

<body>
<table width="100%" border="0" cellspacing="0" cellpadding="0">
  <tr>
    <td width="30%">&nbsp;</td>
    <td width="40%"><?php
						error_reporting(~E_NOTICE); 
						require("../datastore.php");
						if (isset($_POST['login'])){
							$loginsql = "SELECT * FROM admins WHERE username = '".$_POST['userBox']."' AND password = '".$_POST['passBox'] ."'";
							$loginres = mysql_query($loginsql);//echo $loginres;
							$numrows = mysql_num_rows($loginres);//echo $numrows;
								if ($numrows == 1){
									header ("Location:../index.php");	
									exit;								
									}
								else{
									header ("Location:index.php?error=1");
									exit;
									}							
							}	
					?></td>
    <td width="30%">&nbsp;</td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><form id="form1" name="form1" method="post" action="index.php">
      <table width="100%" border="0" cellspacing="0" cellpadding="0">
        <tr>
          <td width="33%">Username</td>
          <td width="67%"><input type="text" name="userBox" id="userBox" /></td>
        </tr>
        <tr>
          <td>Password</td>
          <td><input type="password" name="passBox" id="passBox" /></td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
        </tr>
        <tr>
          <td><input type="submit" name="login" id="login" value="Login" /></td>
          <td>&nbsp;</td>
        </tr>
      </table>
    </form></td>
    <td>&nbsp;</td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><?php if (isset($_GET['error'])){echo "<strong>Incorrect username/Password.</strong>";}?></td>
    <td>&nbsp;</td>
  </tr>
</table>
</body>
</html>