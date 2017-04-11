<?php 
error_reporting(~E_NOTICE);   
require_once("../datastore.php");
$error_msg = "";
$cid = "";
$catsql = "SELECT * FROM categories order by id asc";
$catres = mysql_query($catsql);
$numrows = mysql_num_rows($catres);
$cid = $_GET['cid'];
	if($numrows == 0)
	{
		$error_msg= "&nbsp;No Categories Found";
	}
	else{
				echo "<select name=\"cat\" id=\"cat\"  onChange=\"showCategory(this.value)\">";//
				echo "<option value=\"null\">Select....</option>";
		while($catrow = mysql_fetch_assoc($catres))
			{
				if ($catrow['id'] == $cid){//this if/else is for simple Javascript instead of Ajax
								echo "<option value=\"".$catrow['id']."\" selected=\"selected\">".$catrow['name']."</option>";
				}
				else{
								echo "<option value=\"".$catrow['id']."\">".$catrow['name']."</option>";
				}
			} 
				echo "</select>";
	}
?>
                                    
		           