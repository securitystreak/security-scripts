<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <script src="js/jquery-1.5.1.js"></script>  
  <script>
  $(document).ready(function(){    
		$(document.body).click(function () {
		  $("div:hidden:first").fadeIn("slow");
		});
  });
  </script>
  <style>
  span { color:red; cursor:pointer; }
  div { margin:3px; width:80px; display:none;height:80px; float:left; }
  div#one { background:#f00; }
  div#two { background:#0f0; }
  div#three { background:#00f; }
  </style>
</head>
<body>
  <span>Click here...</span>
  <div id="one"></div>
  <div id="two"></div>
  <div id="three"></div>
</body>
</html>
