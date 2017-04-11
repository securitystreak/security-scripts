<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <script src="js/jquery-1.5.1.js"></script>  
  <script>
  $(document).ready(function(){	      
    $(".flip").click(function(){
      $(".panel").slideToggle("slow");
    });
  });
  </script>
<style type="text/css">
div.panel,p.flip{
	margin:0;
	padding:5px;
	text-align:center;
	background:#e5eecc;
	border:solid 1px #c3c3c3;
	}
div.panel{
	height:80px;
	display:none;	
	}
</style>
</head>
<body>
<div class="panel">
  <p>Because time is valueable, we deliver quick and easy learning.</p>
  <p> you can study everything you need to learn.</p>
</div>

<p class="flip">Show / Hide Panel</p>
</body>
</html>
