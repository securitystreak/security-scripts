<?php
      if(isset($_FILES['image'])){
         $filename = $_FILES['image']['name'];
         $tmp=$_FILES['image']['tmp_name'];
         if(!getimagesize($_FILES['image']['tmp_name']))
         {
            echo "Invalid Image File";
exit(0); }
         move_uploaded_file($tmp,"images/".$filename);
         echo "Success";
         exit(0);
} ?>
   <html>
      <body>
         <form action="" method="POST" enctype="multipart/form-data">
            <input type="file" name="image" />
            <input type="submit"/>
         </form>
      </body>
