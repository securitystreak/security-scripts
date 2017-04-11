<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <script src="js/jquery-1.5.1.js"></script>
  
  <script>
  $(document).ready(function(){    
		$("span").click(function () {
			  $(this).fadeOut(1000, function () {
				$("div").text("'" + $(this).text() + "' has faded!");
				$(this).remove();
			  });
		});
		$("span").hover(function () {
		  $(this).addClass("hilite");
		}, function () {
		  $(this).removeClass("hilite");
		});

  });
  </script>
  <style>
  span { cursor:pointer; }
  span.hilite { background:yellow; }
  div { display:inline; color:red; }
  </style>
</head>
<body>
  <h3>Find the modifiers - <div></div></h3>
  <p>
    If you <span>really</span> want to go outside
    <span>in the cold</span> then make sure to wear
    your <span>warm</span> jacket given to you by
    your <span>favorite</span> teacher.
  </p>
</body>
</html>
