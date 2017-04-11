<p>Product&nbsp;Categories</p>
<ul>
<?php
error_reporting(~E_NOTICE);
require_once("datastore.php");
$catsql = "SELECT * FROM categories;";
$catres = mysql_query($catsql);
while($catrow = mysql_fetch_array($catres))
{
echo "<li><a href='index.php?cid=" . $catrow['id'] . "'>". $catrow['name'] . "</a></li>";
}
?>
</ul>