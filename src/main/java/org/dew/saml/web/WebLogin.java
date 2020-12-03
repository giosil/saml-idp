package org.dew.saml.web;

import java.io.*;

import javax.servlet.http.*;

import org.opensaml.saml2.core.AuthnRequest;

import com.lastpass.saml.SAMLIdP;

import javax.servlet.*;

public
class WebLogin extends HttpServlet
{
  private static final long serialVersionUID = 5702414162061073616L;
  
  public
  void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException
  {
    doPost(request, response);
  }
  
  public
  void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException
  {
    String username    = request.getParameter("username");
    String password    = request.getParameter("password");
    String samlRequest = request.getParameter("SAMLRequest");
    String relayState  = request.getParameter("RelayState");
    
    if(username == null || username.length() == 0) {
      sendMessage(request, response, "Invalid username");
      return;
    }
    if(password == null || password.length() == 0) {
      sendMessage(request, response, "Invalid password");
      return;
    }
    if(samlRequest == null || samlRequest.length() == 0) {
      sendMessage(request, response, "Invalid SAMLRequest");
      return;
    }
    
    // TODO: login
    
    SAMLIdP samlIdP = null;
    try {
      samlIdP = SAMLIdP.getInstance();
    }
    catch(Exception ex) {
      sendMessage(request, response, ex);
      return;
    }
    
    AuthnRequest authnRequest = null;
    try {
      authnRequest = samlIdP.validateAuthnRequest(samlRequest);
    }
    catch(Exception ex) {
      sendMessage(request, response, ex);
      return;
    }
    if(authnRequest == null) {
      sendMessage(request, response, "Invalid AuthnRequest");
      return;
    }
    
    String sReqId = authnRequest.getID();
    if(sReqId == null || sReqId.length() == 0) {
      sendMessage(request, response, "Invalid AuthnRequest (missing ID)");
      return;
    }
    String sACS = authnRequest.getAssertionConsumerServiceURL();
    if(sACS == null || sACS.length() == 0) {
      sendMessage(request, response, "Invalid AuthnRequest (missing AssertionConsumerServiceURL)");
      return;
    }
    if(authnRequest.getIssuer() == null) {
      sendMessage(request, response, "Invalid AuthnRequest (missing Issuer)");
      return;
    }
    String sEntityId = authnRequest.getIssuer().getValue();
    if(sEntityId == null || sEntityId.length() == 0) {
      sendMessage(request, response, "Invalid AuthnRequest (missing Issuer Value)");
      return;
    }
    
    String samlReponse = null;
    try {
      samlReponse = samlIdP.generateReponse(sReqId, sEntityId, sACS, username);
    }
    catch(Exception ex) {
      sendMessage(request, response, ex);
      return;
    }
    
    HttpSession httpSession = request.getSession(true);
    if(httpSession != null) httpSession.setAttribute("username", username);
    
    if(relayState == null || relayState.length() == 0) relayState = sEntityId;
    
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    if(WebSSO.DEBUG) {
      out.println("<html><body>");
      out.println("<b>RelayState:</b>: " + relayState + " <br>");
      out.println("<b>SAMLResponse:</b>:<br><br>");
      try {
        out.println(samlIdP.checkResponse(samlReponse).replace("<", "&lt;").replace(">", "&gt;"));
      }
      catch(Exception ex) {
        out.println(ex.toString());
      }
      out.println("<br>");
      out.println("<hr>");
    }
    else {
      out.println("<html><body onload=\"document.forms[0].submit()\">");
    }
    out.println("<form method=\"POST\" action=\"" + sACS + "\">");
    out.println("<input type=\"hidden\" name=\"RelayState\" value=\"" + relayState + "\">");
    out.println("<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + samlReponse + "\">");
    if(WebSSO.DEBUG) {
      out.println("<input type=\"submit\" value=\"Invia\">");
    }
    out.println("</form></body></html>");
  }
  
  protected
  void sendMessage(HttpServletRequest request, HttpServletResponse response, String sMessage)
      throws ServletException, IOException
  {
    if(sMessage == null) sMessage = "";
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<html><body>" + sMessage.replace("<", "&lt;").replace(">", "&gt;") + "</body></html>");
  }
  
  protected
  void sendMessage(HttpServletRequest request, HttpServletResponse response, Exception ex)
      throws ServletException, IOException
  {
    String sMessage = "Exception";
    if(ex != null) {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ex.printStackTrace(new PrintStream(baos));
      sMessage = new String(baos.toByteArray());
    }
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<html><body>" + sMessage.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>") + "</body></html>");
  }
}