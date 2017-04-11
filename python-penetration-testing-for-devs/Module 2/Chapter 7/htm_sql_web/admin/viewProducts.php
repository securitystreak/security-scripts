<?php 
error_reporting(~E_NOTICE);   
//Class object creation
require_once("../datastore.php");
//Step 0 - include pagination class
require_once("../classes/Pagination.php");

/* Step 1 Assign Basic Variables ****/	
$page_limit = 2;
$total = 0;	
$paging = "";
$max_pages = 10;

//Step 2 get total records. 
$cntrs    = mysql_query("SELECT count(*) from products"); 
$totalrow = mysql_fetch_row($cntrs);	
$total  =  $totalrow[0];

//Tell the page name 
$_pageurl = "viewProducts.php";

//Step 3 Create class object	
$paginate = new Paginate($page_limit, $total, $_pageurl, $max_pages);
$paging = $paginate->displayTable();
$page = $paginate->currentPage;
$paginate->start = $paginate->start -1;



$error_msg = "";
$flag = $_GET['flag'];
if($flag==1){
$view_msg = "Product deleted sucessfully!!!!";

}elseif($flag ==2){
$view_msg = "Product edited sucessfully!!!!";

}
$whrstr = "";
if(isset($cid)){$whrstr="AND b.cat_id = $cid";}

$prodsql = "SELECT a.id as cat_id,a.name as cat_name, b.id as prod_id, b.name as prod_name, b.description as prod_desc,"
." b.price as prod_price, b.image as prod_img"
." FROM categories a INNER JOIN products b"
." WHERE a.id = b.cat_id ". $whrstr ."LIMIT $paginate->start, $paginate->limit";

echo $prodsql;
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
		<td width="861" align="center" valign="top">
		
		<table align="center" width="90%" >
	  
		<tr><td colspan="6" align="center"><h4>View Products</h4></td></tr>
		<tr><td colspan="6" align="right"><!--<a href="addCategory.php">Add new Category</a>--></td></tr>
		<tr><td colspan="6" align="center"><?php if($view_msg){?><div align="center" style="background-color:#CCCCCC; color:maroon; font-weight:bold; width:350px; height:40px"><?php echo $view_msg; }?></div></td></tr>
		<tr><td colspan="6" align="center">
	   
		</td></tr>                    
	  <tr>
		<th width="13%" align="left">Category</th>
		<th width="18%" align="left">Product Image</th>
		<th width="16%" align="left">Product Name</th>
		<th width="16%" align="left">Product Price</th>
		<th width="15%" align="left">Product Desc</th>
		<th width="22%" align="left">Actions</th>
		</tr>
	   
   <?php 
   $j = 1;
   while($prodrow = mysql_fetch_array($prodres))
	{
	?>    
	  <tr>                    
		<td><?php echo $prodrow['cat_name']; ?></td>
		<td><?php echo "<img src=\"../Products/".$prodrow['prod_img']."\">"; ?></td>
		<td><?php echo $prodrow['prod_name']; ?></td>
		<td><?php echo "\$".$prodrow['prod_price']; ?></td>
		<td><?php echo $prodrow['prod_desc']; ?></td>
		<td><a href="editProduct.php?cid=<?php echo $prodrow['cat_id'];?>&pid=<?php echo $prodrow['prod_id'];?>">Edit</a> | <a href="deleteProduct.php?pid=<?php echo $prodrow['prod_id']; ?>" onClick="return confirm('This action will delete this product?\n Are you sure to continue?');">Delete</a></td>
	  </tr>                 
	  
	  <?php } ?>
	  <tr>
		<td colspan="6" align="center"><?php echo $paging; ?></td>
		</tr>
						
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
