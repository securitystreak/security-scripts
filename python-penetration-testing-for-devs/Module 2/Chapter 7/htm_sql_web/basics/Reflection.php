<?php
class myparent {
	public $bar;
	public function foo($bar){
		// do stuf
		 $this->bar = $bar;
		 }
}

class mychild extends myparent {
	   public $val;
	   private function bar(myparent &$baz) {
		   // do stuff
		   }
	   public function __construct($val) {
		   $this->val = $val;
		   }
}
	   
	   $child = new mychild('hello world');
	   $child->foo('test')."<br />";
	   
	   $reflect = new ReflectionClass('mychild');
	   echo '<pre>'.$reflect;


		//Reflection::export(new ReflectionClass('mychild'));

$childreflect = new ReflectionClass('mychild');

echo "This class is abstract: ", (int)$childreflect->isAbstract(), "<br />";
echo "This class is final: ", (int)$childreflect->isFinal(), "<br />";
echo "This class is actually an interface: ", (int)$childreflect->isInterface(), "<br />";
echo "\$child is an object of this class: ", (int)$childreflect->isInstance($child), "<br />";
$parentreflect = new ReflectionClass('myparent');

echo "This class inherits from myparent: ", (int)$childreflect->isSubclassOf($parentreflect), "<br />"; /**/

?>