package org.dew.saml.web;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.LogoutRequest;

import com.lastpass.saml.SAMLIdP;

public
class WebSLO extends HttpServlet
{
  private static final long serialVersionUID = -7919655268982000282L;
  
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
    
    LogoutRequest logoutRequest = null;
    try {
      logoutRequest = samlIdP.validateLogoutRequest(sB64SAMLRequest);
    }
    catch(Exception ex) {
      sendMessage(request, response, ex);
      return;
    }
    if(logoutRequest == null) {
      sendMessage(request, response, "Invalid LogoutRequest");
      return;
    }
    if(logoutRequest.getNameID() == null) {
      sendMessage(request, response, "Invalid LogoutRequest (missing NameID)");
      return;
    }
    
    HttpSession httpSession = request.getSession(true);
    if(httpSession != null) {
      httpSession.removeAttribute("username");
    }
    
    sendMessage(request, response, "Logout Effettuato (" + logoutRequest.getNameID().getValue() + ")");
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