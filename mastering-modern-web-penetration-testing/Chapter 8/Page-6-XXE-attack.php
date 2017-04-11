<?php
       $xml = $_POST["xml"];
       $student = simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT); ?>
 <html>
    <title>Name Game</title>
    <body>
<h3> <pre>
Your name is <?php echo $student->name; ?>
            </pre>
        </h3>
    </body></html>