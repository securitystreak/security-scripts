<?php
abstract class animal{
	abstract function getOwned();
	private $age;
	public function __construct($age){
		$this->age=$age;
		}
	public function getAge(){
		return $this->age;
		}
}

interface insurable{
	public function getValue();
	}

class pet extends animal implements insurable{
	private $name;
	public function __construct($name,$age){
		parent :: __construct($age);
		$this->name = $name;
		}
	public function getName(){
		return $this->name;
		}
	public function getOwned(){
		return ("Owner String");
		}
	public function getValue(){
		return ("Priceless");
		}
	}

class house implements insurable{
	public function getValue(){
		return ("Rising fast");
		}
	}
	
//$dog= new animal(5);
$cat = new pet("Kattey",2);
echo $cat->getName()."<br />";
echo $cat->getAge()."<br />";
echo $cat->getOwned()."<br />";
echo $cat->getValue()."<br />";
/**/
$construct = new house;
echo $construct->getValue();/**/

?>