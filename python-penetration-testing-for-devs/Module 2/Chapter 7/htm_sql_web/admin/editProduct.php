<?php
 error_reporting(~E_NOTICE);
 
 //Class object creation
 require_once("../classes/Product.php");
 require_once("../datastore.php");
 
 $prod = new Product();
 
 $cid = intval($_GET['cid']);
 $pid = intval($_GET['pid']);
 $error_msg = "";
 $dir = "../Products/";
 if($_POST['sub']){
   
   $pName = trim($_POST['pName']);
   $pDesc = trim($_POST['pDesc']);
   $pPrice = trim($_POST['pPrice']);
   $cat_id    = ($_POST['cid']);
   $prod_id    = ($_POST['pid']);
   $existingImg = trim($_POST['existingImg']);
   //Validation
   echo $cat_id;
   if((!$pName)||(!$pDesc)||(!$pPrice)){
     $error_msg  = "&nbsp;All Fields are Mandatory.";
   }
      
   
   if(!$error_msg){
     //Calling setter function
	 $prod->setpName($pName);	 
	 $prod->setpPrice($pPrice);
	 $prod->setpDesc($pDesc);
	 $prod->setCID($cat_id);
	 $prod->setPID($prod_id);
	 
    if(is_uploaded_file($_FILES['pImg']['tmp_name'])){
	 		
			$filename = $_FILES['pImg']['name'];
			
			if(move_uploaded_file($_FILES['pImg']['tmp_name'],$dir.$filename)){
			 	$prod->setpImage($filename);
			}else{
				echo "File not uploaded";
				
			}
	 }else{
	 	$prod->setpImage($existingImg);
	 
	  }	  
	  
	  //Datbase insertion code here
	  $pname  = $prod->getpName();
	  $pimg   = $prod->getpImage();
	  $pprice = $prod->getpPrice();
	  $pdesc  = $prod->getpDesc();	  
	  $cid    = $prod->getCID();
	  $pid    = $prod->getPID();
	  
	 $sql = "UPDATE products SET cat_id = \"$cid\",name = \"$pname\" ,description = \"$pdesc\" ,image = \"$pimg\",price = \"$pprice\" WHERE id = $pid";
	 
	 echo  $sql;
	 if(mysql_query($sql)){
	 
	 	header("Location: viewProducts.php?flag=2");
		exit;
		
	 
	 }else{
	 
	 echo "error  ";
	 }   
   } 
 } 
//Pick existing data
 
 $select = "select * from products where id = $pid";
 $rs = mysql_query($select);
 $row = mysql_fetch_row($rs);
 //$id = $row[0];
 $pdbName = $row[2]; 
 $pdbImg = $row[3];
 $pdbPrice = $row[4];
 $pdbDesc = $row[5];
// $filename = $row[2];
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
                    <form name="form1" action="editProduct.php" method="post" enctype="multipart/form-data">
                    <table align="center" width="80%" >
                  
                    <tr><td colspan="2" align="center"><h4>Edit Product</h4></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    <tr><td colspan="2" align="center"><?php if($error_msg){?><div align="center" style="background-color:#CCCCCC; color:maroon; font-weight:bold; width:350px; height:40px"><?php echo $error_msg; }?></div></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>
                    
                    
                    <tr>
                    <td>Select Category</td>
                      <td><?php require("getCategoryList.php");?></td>
                    <td width="22%">Product Name</td>
                    
                    <td width="78%"><input type="text" name="pName" value="<?php echo $pdbName; ?>" /></td>
                    
                    </tr>
                    
                    
                    <tr>
                      <td valign="top">Product Description</td>
                      <td><textarea name="pDesc" cols="" rows="3" value="" ><?php echo $pdbDesc; ?></textarea></td>
                    </tr>
                    <tr>
                      <td>Product Price</td>
                      <td><input type="text" name="pPrice" value="<?php echo $pdbPrice; ?>" /></td>
                    </tr>
                    <tr>
                    <td>Product image</td>
                    
                    <td><input type="file" name="pImg" />
                    <input type="text" name="cid" value="<?php echo $cid; ?>" /> 
                    <input type="text" name="pid" value="<?php echo $pid; ?>" />                    
                    <input type="text" name="existingImg" value="<?php echo $pdbImg; ?>" />
                    </td>
                    
                    </tr>
                    <tr>
                      <td>Existing Image</td>
                      <td><img src="<?php echo $dir.$pdbImg; ?>" /></td>
                    </tr>
                    
                    <tr>
                    <td>&nbsp;</td>
                    
                    <td><input type="submit" name="sub" width="19" height="48" class="button"  value="Edit Product" />&nbsp;<input type="button" name="sub" class="button" value="Back" onClick="window.location = 'viewProducts.php'" /></td>
                    
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