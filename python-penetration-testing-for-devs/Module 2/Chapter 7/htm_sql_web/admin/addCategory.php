<?php
 error_reporting(~E_NOTICE);
 session_start();
 //Class object creation
 require_once("../classes/Category.php");
 require_once("../datastore.php");
 
 $cat = new Category; 
 $error_msg = "";
 $cName = "";
 //$dir = "../pImages/";
 if($_POST['sub']){
   
   $cName = trim($_POST['cName']);
   //Validation
   
   if(!$cName){
     $error_msg  = "&nbsp;Category name cannot be left blank.";
   }
   
   
   if(!$error_msg){
     //Calling setter function
	 $cat->setcName($cName);   
	  
	  //Database insertion code here
	  $cname = $cat->getcName();
	 // $img = $cat->getcImage();
	  
	 echo  $sql = "insert into categories (name) values (\"$cname\") ";
	 
	 
	 if(mysql_query($sql)){
	 
	 	header("Location: viewCategory.php");
		exit;
		
	 
	 }else{
	 
	 echo "error  ";
	 }   
   } 
 } 
?>
<html>
<head>
<title>Administration Panel</title>
<link rel="stylesheet" type="text/css" href="styles/admin.css"/>
</head>
<body>
	<table cellspacing="0" cellpadding="0" class="maintbl" align="center">
		<tr>
		  <td class="logo"> Administration Area</td>
	  </tr>
		<tr>
			<td class="topnav" align="left">&nbsp;</td>
		</tr>
		<tr>
			<td class="middlearea" valign="top">
			<table cellspacing="0" cellpadding="10" width="100%" height="100%">
				<tr>
			    	<td width="172" valign="top" id="leftnav"><?php require("leftmenu.php");?></td>
			        <td width="882" align="center" valign="top">
                    <form name="form1" action="addCategory.php" method="post" enctype="multipart/form-data">
                    <table align="center" width="60%" >
                  
                    <tr><td colspan="2" align="center"><h4>Add Category</h4></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    <tr><td colspan="2" align="center"><?php if($error_msg){?><div align="center" style="background-color:#CCCCCC; color:maroon; font-weight:bold; width:350px; height:40px"><?php echo $error_msg; }?></div></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    
                    <tr>
                    <td>Category Name</td>
                    
                    <td><input type="text" name="cName" value="<?php echo $cName; ?>" /></td>
                    
                    </tr>
                    
                    <tr>
                    <td>&nbsp;</td>
                    
                    <td><input type="submit" name="sub" class="button" value="Add Category" />&nbsp;<input type="button" name="sub" class="button" value="Back" onClick="window.location = 'viewCategory.php'" /></td>
                    
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
</body>
</html>