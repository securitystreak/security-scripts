<link rel="stylesheet" type="text/css" href="../css/admin.css" />
<?php  
error_reporting(~E_NOTICE);
session_start();
if(isset($_SESSION['username'])){	
?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="">
	<tr>
		<td width="528" height="19" valign="top" class="error" style="padding-left:10px;">
		<a href="maincontent.php">Home</a></td>
	</tr>
    <tr>
		<td width="528" height="19" valign="top" class="error" style="padding-left:10px;">
		<a href="addCategory.php">Add Category</a></td>
	</tr>
    <tr>
		<td width="528" height="19" valign="top" class="error" style="padding-left:10px;">
		<a href="viewCategory.php">View Categories</a></td>
	</tr>
    <tr>
      <td width="528" height="19" valign="top" class="error" style="padding-left:10px;"><a href="addProduct.php">Add Products</a></td>
    </tr>
    <tr>
		<td width="528" height="19" valign="top" class="error" style="padding-left:10px;">
		<a href="viewProducts.php">View Products</a></td>
	</tr>
  
	<tr>
		 <td height="19" valign="top" style="padding-left:10px;" class="error"><a href="logout.php">Logout</a> </td>
	</tr>
	
	<tr>
		 <td height="37" colspan="3" valign="top">&nbsp;</td>
	</tr>
</table>
<?php
}
?>
