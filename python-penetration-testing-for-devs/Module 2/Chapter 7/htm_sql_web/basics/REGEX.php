<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>
<body>
<?php

$foods = array("pasta", "steak", "fish", "potatoes");
$menu = preg_grep("/^p/", $foods);
print_r($menu);
echo "<br />";

$subject = "abcdef";
$pattern = '/^def/';
preg_match($pattern, substr($subject,3), $matches);
print_r($matches);
echo "<br />";

$delimitedText = "+Jason+++Gilmore+++++++++++Columbus+++OH";
$fields = preg_split("/\+{1,}/", $delimitedText);
print_r($fields);
foreach($fields as $field) 
echo $field."<br />";

?>
</body>
</html>