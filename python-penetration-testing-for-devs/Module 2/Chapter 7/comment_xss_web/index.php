

<html>
<body background="wel.jpg">

<h1>Leave your Comments </h1>
<br>
<form Name="sample" action="submit.php" onsubmit="return validateForm()" method="POST">

<table-cellpadding="3" cellspacing="4" border="0">

<tr>
<td> <font size= 4><b>Your name:</b></font></td>
<td><input type="text" name="name" rows="10" cols="50"/></td>
</tr>
<br><br>


<tr valign= "top"> <th scope="row"  <p class="req">
<b><font size= 4>Comments</font> </b> </p> </th>

<td> <textarea class="formtext" tabindex="4" name="comment" rows="10" cols="50"></textarea></td>


</tr>


<tr>

<td> <input type="Submit" name="submit" value="Submit" /> </td>

</tr>
</table>
</form>
<br>

<font size= 4 ><a href="dis.php"> Old comments </a> 


<SCRIPT LANGUAGE="JavaScript">
    <!-- Hide code from non-js browsers
    function validateForm()
    {
        formObj = document.sample;

if((formObj.name.value.length<1) || (formObj.name.value=="HACKER"))
{
alert("Enter your name");
return false;
}
if(formObj.comment.value.length<1)
{
alert("Enter your comment.");
return false;
}


      
    }
    // end hiding -->
</SCRIPT>

</body>
</html>



