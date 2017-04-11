<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
</head>
<body>
<?php 
/*$myFile = "testFile.txt"; 
$fh = fopen($myFile, 'w') or die("can't open file"); 
$stringData = "Bobby Bopper\n"; 
fwrite($fh, $stringData); 
$stringData = "Tracy Tanner\n"; 
fwrite($fh, $stringData);
fclose($fh); 

$fh = fopen($myFile, 'a') or die("can't open file"); 
$stringData = "Floppy Jalopy\n"; 
fwrite($fh, $stringData); 
$stringData = "Pointy Pinto\n"; 
fwrite($fh, $stringData);
fclose($fh); */

/*$myFile = "testFile.txt"; 
$fh = fopen($myFile, 'a') or die("can't open file");
ftruncate($fh,0);*/

#Reading a File Line by Line
/*$file = fopen("testFile.txt", "r") or exit("Unable to open file!");
		//Output a line of the file until the end is reached
		while(!feof($file)){
			echo fgets($file). "<br />";
		}
fclose($file); */

#Reading a File Character by Character
/*$file = fopen("testFile.txt", "r") or exit("Unable to open file!");
		//Output a line of the file until the end is reached
		while(!feof($file)){
			echo fgetc($file). "<br />";
		}
		fclose($file); 
echo filesize("testFile.txt");*/
#Create Text File Counter
/*$file = fopen("counter.txt", 'a+');
	
	if ($file == false) {
	         die ("Unable to open/create file");
	}
	if (filesize("counter.txt") == 0) {
	          $counter = 0;
	} else {
	         $counter = (int) fgets($file);
	}

	ftruncate($file, 0);
	              $counter++;
	fwrite($file, $counter);
	
	echo "There has been $counter hits to this site.";*/
	
#Read from Comma Seprated Values(CSV) File generated from MYSQL
/*$file = fopen("admins.csv","r");
print_r(fgetcsv($file));
fclose($file); 

#Read from your own CSV File
$file = fopen("contacts.csv","r");
while(!feof($file)){
	print_r(fgetcsv($file));
	}
fclose($file);*/

//$line = "";
//$file = "";

#Create your own CSV File from Array
/*$list = array("Peter,Griffin,Oslo,Norway","Glenn,Quagmire,Oslox,Norway");
	$file = fopen("contacts.csv","w+");
	foreach ($list as $line)
	{fputcsv($file,preg_split("/,/",$line));}
fclose($file); */

#Read the file
//echo readfile("testFile.txt")."<br />";
//echo file_get_contents("testFile.txt");

#Add contents using constants
/*$data = "My Data";
file_put_contents("testFile.txt", $data, FILE_APPEND);
$data = array("More Data", "And More", "Even More");
file_put_contents("testFile.txt", $data, FILE_APPEND);
*/
#Directory Handling

echo getcwd()."<br />";
//mkdir('public_html');
chdir('public_html');
echo getcwd()."<br />";
	fopen("test.txt","w+");
unlink("test.txt");
chdir('F:\PHPMYSQL90\23-12-11\basics');
rmdir('public_html');
echo getcwd()."<br />";/**/

?>
</body>
</html>