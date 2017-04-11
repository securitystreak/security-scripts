<?php
 error_reporting(~E_NOTICE);
 
 //Class object creation
 require_once("../classes/Product.php");
 require_once("../datastore.php");
 
 $prod = new Product();
 
 $error_msg = "";
 $dir = "../Products/";
 if($_POST['sub']){
   
   $pName = trim($_POST['pName']);
   $pDesc = trim($_POST['pDesc']);
   $pPrice = trim($_POST['pPrice']);
   $cat_id    = ($_POST['cid']);
   //Validation
   echo $cat_id;
   if((!$pName)||(!$pDesc)||(!$pPrice)){
     $error_msg  = "&nbsp;All Fields are Mandatory.";
   }
      
   
   if(!$error_msg){
     //Calling setter function
	 $prod->setpName($pName);
	 $prod->setpDesc($pDesc);
	 $prod->setpPrice($pPrice);
	 $prod->setCID($cat_id);
	 
    if(is_uploaded_file($_FILES['pImg']['tmp_name'])){
	 		
			$filename = $_FILES['pImg']['name'];
			
			if(move_uploaded_file($_FILES['pImg']['tmp_name'],$dir.$filename)){
			 	$prod->setpImage($filename);
			}else{
				echo "File not uploaded";
				
			}
	 }else{
	 	$prod->setpImage("");
	 
	  }	  
	  
	  //Datbase insertion code here
	  $pname  = $prod->getpName();
	  $pdesc  = $prod->getpDesc();
	  $pprice = $prod->getpPrice();
	  $pimg   = $prod->getpImage();
	  $cid    = $prod->getCID();
	  
	 $sql = "insert into products (cat_id,name,description,image,price) values (\"$cid\",\"$pname\",\"$pdesc\",\"$pimg\",\"$pprice\") ";
	 
	 echo  $sql;
	 if(mysql_query($sql)){
	 
	 	header("Location: viewProducts.php");
		exit;
		
	 
	 }else{
	 
	 echo "error  ";
	 }   
   } 
 } 
?>
<html>
<head>
<title>Administration Area</title>
<link rel="stylesheet" type="text/css" href="styles/admin.css"/>
<script type="text/javascript">
function showCategory(str)
{
	//var DataToSend = "cid="+str; alert(str);
if (window.XMLHttpRequest)
  {// code for IE7+, Firefox, Chrome, Opera, Safari
  xmlhttp=new XMLHttpRequest();
  }
else
  {// code for IE6, IE5  
  xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
  //alert("hello");
  }  
  document.getElementById("cid").value=str;
xmlhttp.submit;
}
</script>
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
                    <form name="form1" action="addProduct.php" method="post" enctype="multipart/form-data">
                    <table align="center" width="80%" >
                  
                    <tr><td colspan="2" align="center"><h4>Add Product</h4></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    <tr><td colspan="2" align="center"><?php if($error_msg){?><div align="center" style="background-color:#CCCCCC; color:maroon; font-weight:bold; width:350px; height:40px"><?php echo $error_msg; }?></div></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    
                    <tr>
                      <td>Select Category</td>
                      <td><?php require("getCategoryList.php");?></td>
                    </tr>
                    <tr>
                    <td width="22%">Product Name</td>
                    
                    <td width="78%"><input type="text" name="pName" value="<?php echo $pName; ?>" /></td>
                    
                    </tr>
                    
                    
                    <tr>
                      <td valign="top">Product Description</td>
                      <td><textarea name="pDesc" cols="" rows="3" value="<?php echo $pDesc; ?>" ></textarea></td>
                    </tr>
                    <tr>
                      <td>Product Price</td>
                      <td><input type="text" name="pPrice" value="<?php echo $pPrice; ?>" /></td>
                    </tr>
                    <tr>
                    <td>Product image</td>
                    
                    <td><input type="file" name="pImg" /><input type="text" name="cid" id="cid" value="<?php echo $_REQUEST['cid']; ?>" /></td>
                    
                    </tr>
                    
                    <tr>
                    <td>&nbsp;</td>
                    
                    <td><input type="submit" name="sub" class="button" value="Add Product" />&nbsp;<input type="button" name="sub" class="button" value="Back" onClick="window.location = 'viewProduct.php'" /></td>
                    
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