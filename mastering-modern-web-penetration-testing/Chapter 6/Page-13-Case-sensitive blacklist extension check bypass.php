 <?php
      if(isset($_FILES['image'])){
         $filename = $_FILES['image']['name'];
         $tmp=$_FILES['image']['tmp_name'];
         $ext=end(explode('.',$_FILES['image']['name']));
         $blacklist= array("php","php3","phtml","php4");
         if(in_array($ext,$blacklist)){
            echo "Not allowed!";
exit(0); }
         move_uploaded_file($tmp,"images/".$filename);
         echo "Success";
         exit(0);
} ?>
       <html>
       <body>
           <form action="" method="POST" enctype="multipart/form-data">
               <input type="file" name="image" />
               <input type="submit" />
           </form>
       </body>
       </html>