<?php

/**
 * 
 * Usage example:
 * $paginate = new Paginate(10, 21, "http://someurl.php?param=value", 20); echo
 * $paginate->displayUl();
 * Suggest you wrap output in a div with class 'pagination' and...
 * 
 * Use CSS to change appearance of HTML:
 * .pagination ul{
 * 	 border-bottom: 1px solid #ccc; 
 * 	 margin:0;
 * 	 padding:1%; 
 * 	 margin-bottom:2%; 
 * 	 list-style-type: none;
 * 	 background: #f1f1f1;
 * }
 * .pagination ul li{
 * 	 list-style-image: none;
 * 	 display:inline;
 * 	 padding-left: 1%; 
 * 	 line-height: 1.2em;
 * }
 */

 class Paginate{
     
     //Set some default values and define the variables being used by the class
     public $start = 1;
     public $limit = 10;
     public $num = 0;
     public $url = "";
     public $maxPages = 20;
	 public $urlAppendString = "";
     //public $class = "tb_blue_td";
     
     public $numPages = 0;
     public $currentPage = 1;
     
     
     /**
      * @param $limit - The number of records per page, 
      * @param $num - The total number of records.
      * @param $url - The url that underpins the links (with parameters)
	  * @param $maxPages - The max number of pages support.
      */
     function __construct($limit, $num, $url, $maxPages){
         
         //We get the start number from the URL. Casting to int makes it safe
         if (isset($_GET['start'])){
             $this->start = (int) $_GET['start'];
         }
         //$this->start = 11;
         $this->limit = (int) $limit;
         $this->num = (int) $num;
         $this->url = $url;
         $this->maxPages = (int) $maxPages; //set to a default value of 20
         
         //The URL might not have any parameters, but since we need to add one,
         //we must know whether to append a ? or a &
         $this->interpretUrl();
         $this->calculate_numPages();
         $this->calculateCurrent();
     }
     
     /**
      * Check if the URL already has parameters.  Set an instance variable
      * with ? or & accordingly
      */
     function interpretUrl(){
         //Check if we need to add ? or & to the end of the url to add start
         //parameter.
         if (strstr ($this->url, "?")){
             $this->urlAppendString = "&";
         } else {
             $this->urlAppendString = "?"; 
         }
     }
     
     
     /**
      * Determine number of pages that should be displayed.
      */
     function calculate_numPages(){
         $this->numPages = ceil($this->num / $this->limit);
     }
     
     
     /**
      * Determine if current page is greater than page 1
      */
     function calculateCurrent(){
         if ($this->start > $this->limit){
            $this->currentPage = ceil($this->start / $this->limit);
         } 
     }
     
     
     /**
      * Return html link for Previous Page
      * @return String (html)      
      */
     function getPreviousPage(){
         if ($this->currentPage > 1){
             return "<a href='".$this->url.$this->urlAppendString."start=".
             ($this->start-$this->limit).
             "' title='Previous page'>&lt;Previous page</a>";
         }
     }
     
     
     /**
      * Return html link for Next Page
      * @return String (html)
      */
     function getNextPage(){
         if ($this->currentPage < $this->numPages){
             return "<a href='".$this->url.$this->urlAppendString."start=".
             ($this->start+$this->limit).
             "' title='Next page'>&gt;Next page</a>";
         }
     }
     
     /**
      * getFirstPage 
      * @return String (html) Start is always 1.
      */
     function getFirstPage(){
         if ($this->currentPage > 1){//If not on first page already
             return "<a href='".$this->url.$this->urlAppendString."start=1' 
             title='First page'>&lt;&lt;First page</a>";
         }
     }
     
     /**
      * getLastPage
      * @return String (html)
      */
     function getLastPage(){
         /*
          * This uses fmod to work out the modulo (remainder) of dividing the 
          * number of records by the max records per page - which is what would
          * appear on the last page - the last page would not normally display
          * the max records per page.  Then, it subtracts this remainder
          * from the number of records and adds 1 to arrive at the start value
          */
         
         if ($this->currentPage < $this->numPages){//If not on last page already
             
             $start_val = (($this->num - fmod($this->num, $this->limit)) + 1);
             
             if ($start_val > $this->num){
             	$start_val = $start_val - $this->limit;
             }
             
             return "<a href='".$this->url.$this->urlAppendString."start=".$start_val
             ."' title='Last page'>&gt;&gt;Last page</a>";
         }
     }     
     
     /**
      * Main method that returns an array of links that are laid out elsewhere
      * @return Array (html strings)      
      */
     function getPaginationLinks(){
         //Don't get carried away with paginating large sets of data.
         //This sets reasonable limits

		 $ar = array();
         
         //Set lower limit 
         //- so we don't start at page 1 link if we're at page 50 of 60
         if(($this->currentPage-ceil($this->maxPages/2))>1){
             $pageStart =($this->currentPage-ceil($this->maxPages/2));
         } else {
             $pageStart = 1;
         }
         
         
         //Set upper limit
         //- so we don't show page 60 link if we're on page 1
         if (($this->currentPage+ceil($this->maxPages/2))<$this->numPages){
             $pageEnd =($this->currentPage+ceil($this->maxPages/2));
         } else {
             $pageEnd = $this->numPages;
         }
         
         /*
          * Create an associative array of links within lower and upper limits
          * We use an associative array because if we create an ordered list
          * for navigation, we need to know which number to seed the ol with
          */
         
         for ($i=$pageStart;$i<=$pageEnd;$i++){
             if ($i == $this->currentPage){
                 $ar[$i] = "[".$i."]";
             } else {
                 $ar[$i] = "<a href='".$this->url.$this->urlAppendString.
                 "start=".((($i-1)*$this->limit)+1)."' 
                 title='Go to page ". $i ."'>".$i."</a>";
             }
         }
         
         return $ar;
     }
     
     /**
      * Returns HTML for navigation.
      * @return String (html)
      */
     function displayUl(){
         /*
          * Get the various html fragments and array of page links. Comment out
          * first, last, previous or next as desired.
          */
         $first = $this->getFirstPage();
         $last = $this->getLastPage();
         $previous = $this->getPreviousPage();
         $next = $this->getNextPage();
         $arLinks = $this->getPaginationLinks();
         
         //Start constructing output
         $output = "<p class='$this->class'>";
         if (isset($first) && $first != ""){
            $output .= "&nbsp;".$first." &nbsp;&bull;";
         }
         if (isset($previous) && $previous != ""){
             $output .= "&nbsp;".$previous."&nbsp;&bull;";
         }
         
         /*
          * Using while in this way is the most efficient way to traverse 
          * the array
          */
         while(list($i, $v) = each($arLinks)){
             $output .= "&nbsp;".$arLinks[$i]."&nbsp;";
         }
         
         if (isset($next) && $next != ""){
             $output .= "&nbsp;".$next."&nbsp;";
         }
         
         if (isset($last) && $last != ""){
             $output .= "&nbsp;".$last."&nbsp;";
         }      
         
         $output .= "</p>";
                  
         return $output;         
     }
     
     /**
      * Returns HTML for navigation.
      * @return String (html)
      */
     function displayOl(){
         /*
          * Get the various html fragments and array of page links. Comment out
          * first, last, previous or next as desired.
          */
         $first = $this->getFirstPage();
         $last = $this->getLastPage();
         $previous = $this->getPreviousPage();
         $next = $this->getNextPage();
         $arLinks = $this->getPaginationLinks();
         
         //Start constructing output
         $output = "<ol start='".key($arLinks)."'>";
         reset($arLinks);
         if (isset($first) && $first != ""){
            $output .= "<div class='navLink'>".$first."</div>";
         }
         if (isset($previous) && $previous != ""){
             $output .= "<div class='navLink'>".$previous."</div>";
         }
         
         /*
          * Using while in this way is the most efficient way to traverse 
          * the array
          */
         while(list($i, $v) = each($arLinks)){
             $output .= "<li>".$arLinks[$i]."</li>";
         }
         
         if (isset($next) && $next != ""){
             $output .= "<div class='navLink'> ".$next."  </div>";
         }
         
         if (isset($last) && $last != ""){
             $output .= "<div class='navLink'>".$last."</div>";
         }      
         
         $output .= "</ol>";
         
         return $output;
         
     }  
     
     
     /**
      * Returns HTML for navigation.
      * @return String (html)
      */     
     function displayTable(){
         /*
          * Get the various html fragments and array of page links. Comment out
          * first, last, previous or next as desired.
          */
         $first = $this->getFirstPage();
         $last = $this->getLastPage();
         $previous = $this->getPreviousPage();
         $next = $this->getNextPage();
         $arLinks = $this->getPaginationLinks();
         
         //Start constructing output
         $output = "<table summary='Pagination table' boreder=1><tr>";
         reset($arLinks);
         if (isset($first) && $first != ""){
            $output .= "<td>".$first."</td>";
         }
         if (isset($previous) && $previous != ""){
             $output .= "<td>".$previous."</td>";
         }
         
         /*
          * Using while in this way is the most efficient way to traverse 
          * the array
          */
         while(list($i, $v) = each($arLinks)){
             $output .= "<td>".$arLinks[$i]."</td>";
         }
         
         if (isset($next) && $next != ""){
             $output .= "<td>".$next."</td>";
         }
         
         if (isset($last) && $last != ""){
             $output .= "<td>".$last."</td>";
         }      
         
         $output .= "</tr></table>";
         
         return $output;
     }
 }

?>
