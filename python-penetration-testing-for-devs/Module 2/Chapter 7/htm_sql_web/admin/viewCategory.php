<?php 
 error_reporting(~E_NOTICE);
 session_start();   
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
$cntrs    = mysql_query("SELECT count(*) from categories"); 
$totalrow = mysql_fetch_row($cntrs);	
$total  =  $totalrow[0];

//Tell the page name 
$_pageurl = "viewCategory.php";

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
 $error_msg = "";
 $catsql = "SELECT * FROM categories order by id asc LIMIT $paginate->start, $paginate->limit";
$catres = mysql_query($catsql);
$numrows = mysql_num_rows($catres);
if($numrows == 0)
{
$error_msg= "&nbsp;No Categories Found";
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
                    
                    <table align="center" width="80%" >
                  
                    <tr><td colspan="4" align="center"><h4>View Categories</h4></td></tr>
                    <tr><td colspan="4" align="right"><!--<a href="addCategory.php">Add new Category</a>--></td></tr>
                    <tr><td colspan="4" align="center"><?php if($error_msg){?><div align="center" style="background-color:#CCCCCC; color:maroon; font-weight:bold; width:350px; height:40px"><?php echo $error_msg; }?></div></td></tr>
                    <tr><td colspan="2" align="center">&nbsp;</td></tr>                    
                  <tr>
                    <th width="16%" align="left">S No</th>
                    <th width="22%" align="left">Name</th>
                    <th width="29%">&nbsp;</th>
                    <th width="33%">&nbsp;</th>
                  </tr>                   
               <?php 
			   $j = 1;
			   while($catrow = mysql_fetch_assoc($catres))
				{
			    ?>    
                  <tr>
                    <td><?php echo $j; ?></td>
                    <td><?php echo $catrow['name']; ?></td>
                    <td></td>
                    <td><?php echo "<a href=addProduct.php?cid=".$catrow['id'].">add Products</a>"; ?></td>
                  </tr>                  
                  <?php $j++; } ?>   
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
