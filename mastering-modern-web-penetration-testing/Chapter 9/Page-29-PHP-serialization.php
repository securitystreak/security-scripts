 <?php
   class Packt
   {
       public $name;
       function __construct($n){
               $this->name = $n;
} }
   $obj = new Packt("PHP Object Injection");
   echo serialize($obj);
?>