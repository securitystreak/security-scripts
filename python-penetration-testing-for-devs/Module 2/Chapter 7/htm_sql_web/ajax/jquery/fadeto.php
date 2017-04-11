<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <script src="js/jquery-1.5.1.js"></script>  
  <script>
  $(document).ready(function(){
	      
    $("p:first").click(function () {
      $(this).fadeTo("slow", 0.33);
    });

  });
  </script>
  
</head>
<body>
  <p>
    Click this paragraph to see it fade.
  </p>
  <p>
    Compare to this one that won't fade.
  </p>
</body>
</html>
