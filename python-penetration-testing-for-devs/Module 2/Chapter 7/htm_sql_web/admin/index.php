<?php
 session_start();
 error_reporting(~E_NOTICE);
 require_once('../datastore.php');
 $error_msg = "";
 $username = "";
 $password = "";
 $remember = "";
 
 if($_POST['sub']){
 
 	//get data
 	$username = strtolower($_POST['username']);
	$password = $_POST['password'];
	
	
	$remember = $_POST['remember'];
	
	
	//validate
	if(!$username){
	
	   $error_msg ="&nbsp;Username cannot be left blank.<br>";
	}
	
	if(!$password){
	   $error_msg .="&nbsp;Password cannot be left blank.<br>";
	
	}
	
	if(!$error_msg){
	 //validate from db
	 
			 echo $sql = "select * from admins where username = \"$username\" and password = \"$password\"";
			 
			 $rs = mysql_query($sql);
			 
					 if(mysql_num_rows($rs) > 0){
				  
						  ///Rememebr Cookie
						  if($remember ==1){
							setcookie("username",$username,time()+86400);
							setcookie("password",$password,time()+86400);
						  }else{
						  
							setcookie("username",$username,time()-172800);
							setcookie("password",$password,time()-172800);					  
						  }
						  
					  ///					
						$row = mysql_fetch_row($rs);
						$id = $row[0];
						$username = $row[1];
						$_SESSION['username'] = $username;
						$_SESSION['id'] =  $id;
						
						header("Location: maincontent.php");
						exit;
						
					  
					 
					 }else{
					 
						  $error_msg = "&nbsp;&nbsp;Username / Passwrod Invalid";	 
					 
					 }	
					 			
			}		
			
} //end of post
		 
		 
		 
if($_COOKIE['username'] && $_COOKIE['password']){
				
	$username = $_COOKIE['username'];
	$password = $_COOKIE['password'];		 
 }
 
 
?>
<html>
<head>
<title>Administration Area</title>
<link rel="stylesheet" type="text/css" href="styles/admin.css"/>
</head>
<body>
	<table cellspacing="0" cellpadding="0" class="maintbl" align="center">
		<tr>
			<td class="logo">
				Administration Area</td>
		</tr>
		<tr>
			<td class="topnav" align="left">&nbsp;</td>
		</tr>
		<tr>
			<td class="middlearea" valign="top">
			<table cellspacing="0" cellpadding="10" width="100%" height="100%">
				<tr>
			    	<td width="180px" valign="top" id="leftnav"><?php include("leftmenu.php");?></td>
			        <td valign="top" align="center">
                    <form name="form1" action="index.php" method="post">
                    <table align="center" width="56%" >
                  
                    <tr><td colspan="2" align="center"><h4>Login</h4></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    <tr><td colspan="2" align="center"><?php if($error_msg){?><div align="center" style="background-color:#CCCCCC; color:maroon; font-weight:bold; width:350px; height:40px"><?php echo $error_msg; }?></div></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    
                    <tr>
                    <td width="20%">Username</td>
                    
                    <td width="80%"><input type="text" name="username" value="<?php echo $username; ?>" /></td>
                    
                    </tr>
                    
                    <tr>
                    <td>Password</td>
                    
                    <td><input type="password" name="password" value="<?php echo $password; ?>" /> </td>
                    
                    </tr>
                    <tr>
                    <td></td>
                    
                    <td><input type="checkbox" name="remember" value="1" /> Remember Me</td>
                    
                    </tr>
                    
                    <tr>
                    <td><input type="submit" name="sub" value="Login" class="button"/></td>
                    
                    <td></td>
                    
                    </tr>
                    
                    </table>
                    
                    </form>
                    
                    </td>
			    </tr>
			</table></td>
		</tr>
		<tr>
			<td class="footer">&nbsp;</td>
		</tr>
	</table>
    <!--<div style="background-color:#003399; width:200px; height:100px; color:#FFFFFF">Div here</div>-->
</body>
</html>