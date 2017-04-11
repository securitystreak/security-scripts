<?php
class Template{	
	public function getHeaderMenu(){
		return array("Home"=>"index.php",
					 "News"=>"news.php",
					 "Reviews"=>"reviews.php",
					 "Ring Tones"=>"rtones.php",
					 "Software"=>"software.php",
					 "Coverage"=>"coverage.php",
					 "Ranking"=>"ranking.php",					 
					 "Contact us"=>"contactus.php");		
		}
	
	public function getAdds(){
		return array("add1_thumb.jpg"=>"add1_detail.jpg",
					 "add2_thumb.jpg"=>"add2_detail.jpg",
					 "add3_thumb.jpg"=>"add3_detail.jpg",
					 "add4_thumb.jpg"=>"add4_detail.jpg");		
	}
	
	public function getFooterMenu(){
		return array("Home"=>"index.php",
					 "News"=>"news.php",
					 "Reviews"=>"reviews.php",
					 "Ring Tones"=>"rtones.php",
					 "Software"=>"software.php",
					 "Coverage"=>"coverage.php",
					 "Ranking"=>"ranking.php",					 
					 "Contact us"=>"contactus.php");		
	}
}
?>