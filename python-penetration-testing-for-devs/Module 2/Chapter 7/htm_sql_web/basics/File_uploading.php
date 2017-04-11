<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>PHP File Uploading</title>
</head>

<body>
<?php
error_reporting(~E_NOTICE);
if(isset($_POST['submit'])){
if ((($_FILES["file"]["type"] == "image/gif"))&& ($_FILES["file"]["size"] < 5242880)){
if ($_FILES["file"]["error"] > 0){
	echo "Error: " . $_FILES["file"]["error"] . "<br />";
	}
	else{
		echo "Upload: " . $_FILES["file"]["name"] . "<br />";
		echo "Type: " . $_FILES["file"]["type"] . "<br />";
		echo "Size: " . ($_FILES["file"]["size"] / 1024) . " Kb<br />";
		echo "Stored in: " . $_FILES["file"]["tmp_name"]."<br />";
		
		if(is_uploaded_file($_FILES['file']['tmp_name'])){
			echo "Temp File ".$_FILES['file']['name']." uploaded successfully.<br />";
			//echo "Displaying contents <br />";
			//readfile($_FILES['file']['tmp_name']);
			}
			else {
				echo "Possible file upload attack: ";
				echo "filename'".$_FILES['file']['tmp_name']."'.";
				}
		if (file_exists("uploaded/" . $_FILES["file"]["name"])){
			echo $_FILES["file"]["name"] . " already exists. ";
			}
			else{
				move_uploaded_file($_FILES["file"]["tmp_name"],"uploaded/".$_FILES["file"]["name"]);
				echo "Stored in: " . "uploaded/" . $_FILES["file"]["name"];
				}				
		
		}
	}
	else{echo "Invalid file";} 
}
 ?>
 <form  enctype="multipart/form-data" action="File_uploading.php" method="post">
            <input type="hidden" name="MAX_FILE_SIZE" value="50000" />
            <input name="file" type="file" />
            <input type="submit" name="submit" value="Send file" />
</form>

</body>
</html>