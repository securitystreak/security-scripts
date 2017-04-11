<?php
class corporatedrone {
	private $employeeid;
	private $tiecolor;
	
	function __clone(){
		$this->tiecolor = "blue";
	}
	
	// Define a setter and getter for $employeeid	
	function setEmployeeID($employeeid) {
		$this->employeeid = $employeeid;
	}	
	function getEmployeeID(){
		return $this->employeeid; 
	}

	// Define a setter and getter for $tiecolor
	function setTiecolor($tiecolor) {
		$this->tiecolor = $tiecolor; 
	}
	function getTiecolor() {
		return $this->tiecolor;	}
}

// Create new corporatedrone object
$drone1 = new corporatedrone();

// Set the $drone1 employeeid member
$drone1->setEmployeeID("12345");

// Set the $drone1 tiecolor member
$drone1->setTiecolor("red");

// Clone the $drone1 object
$drone2 = clone $drone1;

// Set the $drone2 employeeid member
$drone2->setEmployeeID("67890");

// Output the $drone1 and $drone2 employeeid members
echo "drone1 employeeID: ".$drone1->getEmployeeID()."<br />";
echo "drone1 tie color: ".$drone1->getTiecolor()."<br />";
echo "drone2 employeeID: ".$drone2->getEmployeeID()."<br />";
echo "drone2 tie color: ".$drone2->getTiecolor()."<br />";/**/
?>