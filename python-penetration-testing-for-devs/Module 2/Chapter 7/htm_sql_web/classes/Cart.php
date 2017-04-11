<?php
		
	class Cart{
		public $items;		
		public  $lastitemid;		
		function __construct()
		{
			$this->items=array();			
		}		
		#Add items to the cart
		function add_item($prodId, $prodTitle, $prodPrice, $image, $qty)
		{		
		//echo $prodId."tilte".$prodTitle."price".$prodPrice."image".$image."qty".$qty;exit;
				for($i=0;$i<count($this->items);$i++)
				{
					if($this->items[$i][0]==$prodId ){
						$this->items[$i][4]+=$qty;
						$this->items[$i][5]  = $this->items[$i][4]*$this->items[$i][2];
						return;
					}
				}			
			$item = array();			
			$item[0]	=	$prodId;
			$item[1] 	= 	$prodTitle;
			$item[2]	=	$prodPrice;						
			$item[3]	=	$image;
			$item[4]	=	$qty; //Count;	
			$item[5]  	=   $qty*$prodPrice;
			
			$this->lastitemid =	$prodId;		
			array_push($this->items,$item);			
			return;			
		}
		
		#Remove items from the cart
		function remove_item($prodId)
		{
			for($i=0;$i<count($this->items);$i++)
				if($this->items[$i][0]==$prodId)
				{
					print_r($this->items);
					array_splice($this->items,$i,1);
					return 1;
				}					
			return 0;					
		}
		
		#Update items of the cart
		function set_item_count($prodId,$cnt)
		{	
		
			$cnt = intval($cnt);
			
			//var_dump($choiceIds);
			if($cnt<1)
			{
				$this->remove_item($prodId);
				return;
			}			
			for($i=0;$i<count($this->items);$i++)
				if($this->items[$i][0]==$prodId)
				{
					
					$this->items[$i][4]=$cnt;
					$this->items[$i][5]= $this->items[$i][4]*$this->items[$i][2];
					return 1;
				}											
		}
			
			
		#Calculate Grand Total
		function calculate_gTotal()
		{
			$gtotal = 0;
						//print_r($this->items);
			for($i=0; $i<count($this->items); $i++)
			{
				 $gtotal += $this->items[$i][2] * $this->items[$i][4];
			}
			
			return $gtotal;
		}
		
		function calculate_qty()
		{
			$ordqty = 0;
						//print_r($this->items);
			for($i=0; $i<count($this->items); $i++)
			{
				 $ordqty +=  $this->items[$i][4];
			}
			
			return $ordqty;
		}
	
	}
		
	session_start();
	
	if(!$_SESSION['cart'])
		$_SESSION['cart'] = new Cart;
?>