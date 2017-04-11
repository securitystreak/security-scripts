<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Untitled Document</title>
<script type="text/javascript" src=" js/jquery-1.5.1.js "></script>
<script type="text/javascript">
  $(document).ready(function(){
    $("#btn").click(function(){
		$("div").load('testFile.txt');
    });
  });
  </script>
  
</head>
<body>
  <div><h2>Let AJAX change this Text</h2></div>
  <input type="button"  value="Change Content" id="btn"></input>
</body>
</html>