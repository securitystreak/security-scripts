<?php 
//require_once("db.php");
$whrstr="";
if ($_GET['cid']){
	$whrstr="WHERE cat_id =".$_GET['cid'];
}
else {
	$whrstr="";
}
$sql = "Select * from products ".$whrstr;
echo $sql;
$rs = mysql_query($sql);
$dataArray = array();
while($row = mysql_fetch_row($rs)){
	array_push($dataArray,$row);
}
//print_r($dataArray);
?>                
                <table cellpadding="0" cellspacing="0" border="0px" align="left">
                <form name="form1" method="post" action="addtocart.php" >
                <input name="id" type="hidden" value="<?php echo $dataArray[0][0];  ?>" />
                <input name="name" type="hidden" value="<?php echo $dataArray[0][2];  ?>" />
                <input name="image" type="hidden" value="<?php echo $dataArray[0][3];  ?>" />
                <input name="price" type="hidden" value="<?php echo $dataArray[0][4];  ?>" />
                <input name="desc" type="hidden" value="<?php echo $dataArray[0][5];  ?>" />               
                             
                <tr>
                <td><img src="Products/<?php echo $dataArray[0][3];  ?>" height="100px" width="100px" /></td>
                <td valign="top">
                    <table cellpadding="0" cellspacing="0" border="0px" align="left">
                    <tr>
                      <td align="left">&nbsp;</td>
                      <td align="left">Name</td><td align="left"><a href=""><?php echo $dataArray[0][2];?></a></td></tr>
                    <tr>
                      <td align="left">&nbsp;</td>
                      <td align="left">Price</td><td align="left"><?php echo $dataArray[0][4];?></td></tr>                                            
                    <tr>
                      <td align="left" valign="top">&nbsp;</td>
                      <td align="left" valign="top">Description</td><td align="left"><?php echo substr($dataArray[0][5],0,200);?>......</td></tr>
                    <tr><td colspan="3" align="left"><input type="submit" name="sub" value="Add to cart" /></td></tr>
                    </table>
                </td>                            
                </tr>
                </form>                
                <form name="form2" method="post" action="addtocart.php">
                <input name="id" type="hidden" value="<?php echo $dataArray[1][0];?>" />
                <input name="name" type="hidden" value="<?php echo $dataArray[1][2];?>" />
                <input name="image" type="hidden" value="<?php echo $dataArray[1][3];?>" />
                <input name="price" type="hidden" value="<?php echo $dataArray[1][4];?>" />
                <input name="desc" type="hidden" value="<?php echo $dataArray[1][5];?>" />                
                <tr>
                  <td>&nbsp;</td>
                  <td align="left" valign="top">&nbsp;</td>
                </tr>
                <tr>
                <td><img src="Products/<?php echo $dataArray[1][3];  ?>" height="100px" width="100px" /></td>
				<td align="left" valign="top">
                    <table cellpadding="0" cellspacing="0" border="0px">
                    <tr>
                      <td align="left">&nbsp;</td>
                      <td align="left">Name</td><td align="left"><?php echo $dataArray[1][2];?></td></tr>
                    <tr>
                      <td align="left">&nbsp;</td>
                      <td align="left">Price</td><td align="left"><?php echo $dataArray[1][4];?></td></tr>                                             
                    <tr>
                      <td align="left" valign="top">&nbsp;</td>
                      <td align="left" valign="top">Description</td><td align="left"><?php echo substr($dataArray[1][5],0,200);?>......</td></tr>
                    <tr><td colspan="3" align="left"><input type="submit" name="sub" value="Add to cart" /></td></tr>
                    </table>
                </td>
                </tr>
                </form>
</table>                
                