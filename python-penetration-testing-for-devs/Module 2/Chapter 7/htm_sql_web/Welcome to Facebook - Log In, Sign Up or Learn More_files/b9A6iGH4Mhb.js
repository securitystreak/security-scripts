/*!CK:2584115164!*//*1397189772,178183447*/

if (self.CavalryLogger) { CavalryLogger.start_js(["HslKs"]); }

__d("ClientDateVerifier",["BanzaiLogger","Bootloader","ClientDateVerifierConstants"],function(a,b,c,d,e,f,g,h,i){var j={init:function(){var k=Date.now();if(k<i.InvalidTime*1000){if(i.ShouldLog)g.log('ClientDateVerifierLoggerConfig',{client_time:k,invalid_time:i.InvalidTime});if(i.ShowDialog)h.loadModules(["Dialog"],function(l){new l().setTitle(i.DialogTitle).setBody(i.DialogBody).setButtons(l.CLOSE).show();});}}};e.exports=j;});