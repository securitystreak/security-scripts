<?php
   class Packt
   {
       public $name;
       function __construct($n){
               $this->name = $n;
} }
   $stored = 'O:5:"Packt":1:{s:4:"name";s:20:"PHP Object Injection";}';
   $obj = unserialize($stored);
   echo $obj->name; //Displays PHP Object Injection
?>