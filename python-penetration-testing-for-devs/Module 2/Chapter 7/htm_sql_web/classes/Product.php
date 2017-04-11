<?php 
/********Product class**************/

class Product{
	
	private $pid;//modification for editProduct page
	private $pname;		
	private $image;	
	private $price;
	private $description;	
	private $cid;

	public function __construct(){
		$this->pid="";
		$this->pname="";		
		$this->image="";
		$this->price="";
		$this->description="";	
		$this->cid="";		
	}	
	
	public function setPID($p_id){
		$this->pid=$p_id;
	}
	
	public function getPID(){
	 return $this->pid;	
	}
	
	public function setpName($p_name){
		$this->pname=$p_name;	
	}
	
	public function getpName(){
		return $this->pname;
	}
	
		
	public function setpImage($image_name)	{
		$this->image=$image_name;	
	}

	public function getpImage(){
 		return $this->image;	
	}
	
	
	public function setpPrice($p_price){
		$this->price=$p_price;	
	}
	
	public function getpPrice(){
		return $this->price;	
	}	
	
	public function setpDesc($p_desc){
		$this->description=$p_desc;	
	}
	
	public function getpDesc(){
		return $this->description;	
	}
	
	public function setCID($cat_id){
		$this->cid=$cat_id;	
	}
	
	public function getCID(){
		return $this->cid;	
	}

}
?>