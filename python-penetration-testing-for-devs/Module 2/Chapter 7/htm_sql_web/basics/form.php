<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>

<body>

<form action="<?php $_SERVER['SCRIPT_NAME'] ?>" method="post"> 
Gender: 
Male:<input type="radio" value="Male" name="gender">:<br />  
Female:<input type="radio" value="Female" name="gender">:<br /> 

Please choose type of Food::<br />
Steak:<input type="checkbox" value="Steak" name="food[]">:<br />
Pizza:<input type="checkbox" value="Pizza" name="food[]">:<br />
Chicken:<input type="checkbox" value="Chicken" name="food[]">:<br /> 

Select a Level of Education:<br />
<select name="education">
<option value="Jr.High">Jr.High</option>
<option value="HighSchool">HighSchool</option>
<option value="College">College</option></select>

Select your favorite time of day::<br />
<select name="TofD" size="3">
<option value="Morning">Morning</option>
<option value="Day">Day</option>
<option value="Night">Night</option></select>:<br />
<input type="submit" name = "submit" value="Go!" />
</form>


<?php
error_reporting(~E_NOTICE);
if(isset($_POST['submit'])){  
  $gender     = $_POST["gender"];
  $food         = $_POST["food"];
  $quote       = $_POST["quote"];
  $education = $_POST["education"];
  $TofD         = $_POST["TofD"]; 

  echo "You are ".$gender.", and you like ";
	foreach ($food as $f) {
		echo $f."<br />";
		}
  echo "<i>".$quote."</i><br />";
  echo "You're favorite time is ".$TofD.", and you passed ".$education."!<br />"; 
}
?>
</body>
</html>