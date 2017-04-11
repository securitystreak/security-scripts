<?php
class Person {
	private $name;
	function printPersonInfo(){
		echo $this->name . "<br />";		
		}
	
	# Define a setter for the private $name member.
	function setName($name) {		
		 $this->name = $name;
	}
	
	# Define a getter for the private $name member
	function getName() {
		return $this->name;
		}
} #end Person
class EmployedPerson extends Person {
	public  $ocupation;
	public  $company_name;
	public  $business_phone;
	
	function printPersonInfo(){
		parent::printPersonInfo();
		echo $this->occupation . "<br />";
		echo $this->company_name . "<br />";
		echo $this->business_phone . "<br />";
		}
}

$kid = new Person();
$kid->setName("Jimmy");
$kid->printPersonInfo();

$adult = new EmployedPerson();
$adult->setName("Jimmy's Father");

$adult->occupation = "Programmer";
$adult->company_name = "SoftwareDev Ltd";
$adult->business_phone = "444-4444";

$adult->printPersonInfo();/**/

?>