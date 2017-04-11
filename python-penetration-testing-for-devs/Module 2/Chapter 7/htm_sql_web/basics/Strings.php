<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html charset=ISO-8859-1"  />
<title>Untitled Document</title>
</head>

<?php
/*
echo "\x2a";  echo "\055";
echo "<br />";
$thing = "php";
echo $thing;
echo "<br />";
echo $thing[0];
echo $thing[1]; 
echo $thing[2];
//$thing = "php";  
echo $thing;
echo "<br />";      
echo $thing{0};
echo $thing{1};
echo $thing{2};  
echo "<br />"; 
echo strlen("123456");
echo "<br />"; 
$pswd = "supersecret";   
$pswd2 = "supersecreT";
          	if (strcasecmp($pswd,$pswd2) != 0) 
				{echo "Your passwords do not match!";}
			else
				{echo "Your passwords do match!";}
echo "<br />";
echo strspn("Hello world!" , "kHlleo");
echo "<br />";  
echo strcspn("Hello world!" , "w");
echo "<br />"; 
echo strtolower("PAKISTAN");
echo "<br />"; 
echo strtoupper("mosque");
echo "<br />"; 
echo ucfirst("pakistan");
echo "<br />"; 
echo ucwords("welcome to evs institute");
echo "<br />"; 
$recipe = "3 tablespoons Dijon mustard
1/3 cup Caesar salad dressing
8 ounces grilled chicken breast
3 cups romaine lettuce";
// convert the newlines to <br />'s.
echo nl2br($recipe);
echo "<br />"; 
$advertisement = "Coffee at 'Cafè Française' costs $2.25.";
echo htmlentities($advertisement);
echo "<br />"; 
$input = "I just can't get <<enough>> of PHP!";  
echo htmlspecialchars($input);
echo "<br />";
$input = "Email <a href='spammer@example.com'><pre>spammer@example.com</pre></a>";
echo strip_tags($input);
echo "<br />";
echo strip_tags($input, "<a>");
echo "<br />";
$str ="Hello World and welcome to EVS";
$tk = strtok($str," ");
var_dump($tk);
while ($tk != false){
	echo $tk."<br />";
	$tk = strtok(" ");	
	}
parse_str("id=23&name=Kai%20Jim");
echo $id;
echo "<br />";
echo $name;
echo "<br />"; 
$summary = "In the latest installment of the ongoing Developer.com PHP series";
print_r(explode(' ',$summary));
echo "<br />"; 
$cities = array("Columbus", "Akron", "Cleveland", "Cincinnati");
echo implode(" | ", $cities);
echo "<br />"; 
$email = "abc@example.com";          
echo strpos($email, "@");
echo "<br />"; 
$email = "abc@example.com";          
echo stripos($email, "E");
echo "<br />"; 
#Last occurance
$email = "abc@example.com";          
echo strripos($email, "M");
echo "<br />";
$author = "jason@example.com"; 
echo $author = str_replace("@","(at)",$author);
echo "<br />";
echo strstr("Hello World!", "World");
echo "<br />";
echo stristr("Hello World!", "world");
echo "<br />";
$car = "1944 Ford";
echo substr($car, 5);
echo "<br />";
$car = "1944 Ford";
echo substr($car, 0, 4);
echo "<br />";
$car = "1944 Ford";
echo substr_count($car, "4");
echo "<br />";
$car = "1944 Ford";
echo substr_replace($car, "123456", 5);
echo "<br />";
echo str_pad("Salad", 20,"*")." is good.";
echo "<br />";
$who = "World";
echo <<<TEXT
So I said, "Hello $who"
TEXT;
echo "<br />";
*/
#DATE AND TIME
echo (int)checkdate(4, 31, 2005);
// returns false
echo (int)checkdate(02, 29, 2004);
// returns true, because 2004 was a leap yearf
echo (int)checkdate(02, 29, 2005);
// returns false, because 2005 is not a leap year
echo "<br />";
echo "Today is ".date("F d, Y"); 
echo "<br />";
$weekday     = date("l");
$daynumber = date("dS");
$monthyear  = date("F Y");
 printf("Today is %s the %s day of %s", $weekday, $daynumber, $monthyear);
 echo "<br />";
echo "The time is ".date("H:i:s");
echo "<br />";
echo (date_default_timezone_get());
echo "<br />";
$timezone = "Asia/Karachi";
date_default_timezone_set($timezone);
echo "The time is ".date("h:i:sa");
echo "<br />";
print_r (gettimeofday());
echo "<br />";
print_r (getdate());
echo "<br />";
echo $now = mktime();
echo "<br />";
$taxday = mktime(0,0,0,6,30,2012);
// Difference in seconds
echo $difference = $taxday - $now;
echo "<br />";
echo time();

echo date("F d, Y h:i:s", 1322577555);
echo "<br />";
$lastmod = date("F d, Y h:i:sa", getlastmod());
echo "Page last modified on $lastmod";
echo "<br />";
printf("There are %d days in %s.", date("t"), date("F"));
echo "<br />";
$futuredate = strtotime("45 days"); // -45 days as well
echo date("F d, Y", $futuredate);
echo "<br />";
$pastdate = strtotime("-10 weeks 2 days");
echo date("F d, Y", $pastdate);
echo "<br />";




?>