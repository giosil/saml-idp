<%@ page contentType="text/html; charset=UTF-8" %>
<%
  Object username = null;
  if(session != null) username = session.getAttribute("username");
%>
<!DOCTYPE html>
<html lang="en">
<head>
  <title>SAML Identity Provider</title>
</head>
<body>
  <h3>SAML Identity Provider </h3>
  <% if(username != null) { %>
  <b>Username: </b><%= username %>
  <% } else { %>
  <b>User not logged</b>
  <% } %>
</body>
</html>