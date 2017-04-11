<?php 

/******Category Class********/
class Category{
	private $catname;
	private $image;

	//Constructor
	public function __construct()
	{
    	$this->catname="";
    	$this->image="";		
	}	

	//Setters Getters
	public function setcName($cname)
	{
		$this->catname=$cname;
	
	}

	public function getcName()
	{
 		return $this->catname;	
	}

	public function setcImage($image_name)
	{
		$this->image=$image_name;
	
	}

	public function getcImage()
	{
 		return $this->image;	
	}	
	
}

?>