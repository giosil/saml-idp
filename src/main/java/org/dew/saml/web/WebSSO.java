package org.dew.saml.web;

import java.io.*;

import javax.servlet.http.*;

import org.opensaml.saml2.core.AuthnRequest;

import com.lastpass.saml.SAMLIdP;

import javax.servlet.*;

public
class WebSSO extends HttpServlet
{
  private static final long serialVersionUID = 8249566059678441747L;
  
  public static final boolean DEBUG = true;
  
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
    String sRelayState     = request.getParameter("RelayState");
    String sB64SAMLRequest = request.getParameter("SAMLRequest");
    if(sB64SAMLRequest == null || sB64SAMLRequest.length() == 0) {
      sendMessage(request, response, "NO SAMLRequest");
      return;
    }
    
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
      authnRequest = samlIdP.validateAuthnRequest(sB64SAMLRequest);
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
    
    HttpSession httpSession = request.getSession(true);
    if(httpSession != null) {
      Object username = httpSession.getAttribute("username");
      if(username != null) {
        String samlReponse = null;
        try {
          samlReponse = samlIdP.generateReponse(sReqId, sEntityId, sACS, username.toString());
        }
        catch(Exception ex) {
          sendMessage(request, response, ex);
          return;
        }
        
        if(sRelayState == null || sRelayState.length() == 0) sRelayState = sEntityId;
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        if(DEBUG) {
          out.println("<html><body>");
          out.println("<b>RelayState:</b>: " + sRelayState + " <br>");
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
        out.println("<input type=\"hidden\" name=\"RelayState\" value=\"" + sRelayState + "\">");
        out.println("<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + samlReponse + "\">");
        if(DEBUG) {
          out.println("<input type=\"submit\" value=\"Invia\">");
        }
        out.println("</form></body></html>");
        return;
      }
    }
    
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<html><body>");
    out.println("<form method=\"POST\" action=\"/saml-idp/login\">");
    out.println("Username:<br><input type=\"text\" name=\"username\"><br>");
    out.println("Password:<br><input type=\"text\" name=\"password\"><br><br>");
    out.println("<input type=\"hidden\" name=\"SAMLRequest\" value=\"" + sB64SAMLRequest + "\">");
    out.println("<input type=\"hidden\" name=\"RelayState\" value=\"" + sRelayState + "\">");
    out.println("<input type=\"submit\" value=\"Accedi\">");
    out.println("</form>");
    out.println("<hr>");
    out.println("<b>SAMLRequest:</b><br>");
    try {
      out.println("<b>AuthnRequest:</b> " + SAMLIdP.toString(authnRequest).replace("<", "&lt;").replace(">", "&gt;") + "<br>");
    }
    catch(Exception ex) {
    }
    out.println("<b>AssertionConsumerServiceURL:</b> " + sACS + "<br>");
    out.println("<b>Request Id:</b> " + sReqId + "<br>");
    out.println("<b>Issuer Id:</b> " + sEntityId + "<br><br>");
    out.println("<b>RelayState:</b> " + sRelayState + "<br>");
    out.println("</body></html>");
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
      sMessage = new String(baos.toByteArray()).replace("\n", "<br>");
    }
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<html><body>" + sMessage.replace("<", "&lt;").replace(">", "&gt;") + "</body></html>");
  }
}