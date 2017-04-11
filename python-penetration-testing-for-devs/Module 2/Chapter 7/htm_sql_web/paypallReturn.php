<?PHP		
include("datastore.php");	
	$_orderid = "";
	$_status = "";
	$req 		= 'cmd=_notify-validate';
	
	foreach ($_POST as $key => $value) {
		$value	= urlencode(stripslashes($value));
		$req 	.= "&$key=$value";
	}
	
	$_orderid		= $_POST['invoice'];
	$_status		= $_POST['payment_status'];
	$_trans_id 	    = $_POST['txn_id'];
	$r_email 		= $_POST['receiver_email'];
	
	 
	$header .= "POST /cgi-bin/webscr HTTP/1.0\r\n";
	$header .= "Content-Type: application/x-www-form-urlencoded\r\n";
	$header .= "Content-Length: " . strlen($req) . "\r\n\r\n";

	//$fp = fsockopen ('www.paypal.com', 80, $errno, $errstr, 30);
	$fp = fsockopen ('www.paypal.com', 80, $errno, $errstr, 30);

	//echo  $fp;
	if (!$fp){
		
		$mess	= "This transaction was unsuccessful. Please contact the merchant by clicking <a href='mailto:$_email'>here</a>";
	} 
	else {
		fputs ($fp, $header . $req);
		$confirm = false;
		while (!feof($fp)) {
			
			$res = fgets ($fp, 1024);
			if (strcmp ($res, "VERIFIED") == 0) {
				if($_status == 'Completed'){
					$confirm  = true;					
						$query	  =	"Update order set orderstatus = 'c' where id = $_orderid";					
				}
				else {
						$query	=	"Update order set status = 't'  where id = $_orderid";
				}
			}
			
			else if (strcmp ($res, "INVALID") == 0){
				
				$query	= "Update order set orderstatus = 't' where id = $_orderid";
			}
		}
		fclose($fp);
		
		/*if(mysql_query($query) && $confirm){
		}
		else {
			mysql_query($query) ;
		}*/
	}
	
	
	

?>