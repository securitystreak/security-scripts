<?php 
 error_reporting(~E_NOTICE);  
 require_once("../datastore.php");
 $error_msg = "";
 $prodsql = "SELECT a.name as cat_name, b.name as prod_name, b.description as prod_desc,"
           ." b.price as prod_price, b.image as prod_img"
		   ." FROM categories a INNER JOIN products b"
		   ." WHERE a.id = b.cat_id";

$prodres = mysql_query($prodsql);
$numrows = mysql_num_rows($prodres); //echo $numrows;
if($numrows == 0)
{
$error_msg= "&nbsp;No Products Found";
}
else
?>
<html>
<head>
<title>Administration Area</title>
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
			    	<td width="193" valign="top" id="leftnav"><?php include("leftmenu.php");?></td>
			        <td  align="center" valign="top">
                    
                    <table align="center" width="100%" >
                  
                    <tr><td colspan="5" align="center"><h4>View Products</h4></td></tr>
                    <tr><td colspan="5" align="right"><!--<a href="addCategory.php">Add new Category</a>--></td></tr>
                    <tr><td colspan="5" align="center"><?php if($error_msg){?><div align="center" style="background-color:#CCCCCC; color:maroon; font-weight:bold; width:350px; height:40px"><?php echo $error_msg; }?></div></td></tr>
                    <tr>
                      <td colspan="5" align="center">&nbsp;</td>
                    </tr>
                    <tr><td colspan="5" align="left">&nbsp;</td></tr>
                    
                  <tr>
                    <th width="16%" align="left">Category</th>
                    <th width="22%" align="left">Product Image</th>
                    <th width="20%" align="left">Product Name</th>
                    <th width="20%" align="left">Product Price</th>
                    <th width="20%" align="left">Product Description</th>                    
                  </tr>
                   
               <?php 			   
			   while($prodrow = mysql_fetch_array($prodres))
				{
			    ?>    
                  <tr>                    
                    <td><?php echo $prodrow['cat_name']; ?></td>
                    <td><?php echo "<img src=\"../Products/".$prodrow['prod_img']."\""; ?></td>
                    <td><?php echo $prodrow['prod_name']; ?></td>
                    <td><?php echo $prodrow['prod_price']; ?></td>
                    <td><?php echo $prodrow['prod_desc']; ?></td>
                  </tr>
                  
                  <?php } ?>
                                    
		           </table>             
                    
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
