package com.lastpass.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

import java.net.URL;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.util.Calendar;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

import org.opensaml.Configuration;

import org.opensaml.common.SAMLObject;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;

import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import org.xml.sax.InputSource;

@SuppressWarnings("deprecation")
public class SAMLIdP {
  
  private BasicParserPool parsers;
  private static SAMLIdP _instance;
  
  public boolean signResponse     = true;
  public boolean signAssertion    = false;
  public boolean encryptAssertion = false;
  public boolean extraAttributes  = false;
  public String  issuer           = "http://localhost:8080/saml-idp/metadata.xml";
  
  public SAMLIdP() {
    // create xml parsers
    parsers = new BasicParserPool();
    parsers.setNamespaceAware(true);
  }
  
  // [dew]
  public static SAMLIdP getInstance() 
      throws Exception
  {
    if(_instance != null) return _instance;
    SAMLInit.initialize();
    _instance = new SAMLIdP();
    return _instance;
  }
  
  public AuthnRequest validateAuthnRequest(String authnRequest)
      throws SAMLException
  {
    byte[] decoded = DatatypeConverter.parseBase64Binary(authnRequest);
    
    byte[] inflated;
    try {
      inflated = inflate(decoded);
    } catch (IOException e) {
      throw new SAMLException(e);
    } catch (DataFormatException e) {
      throw new SAMLException(e);
    }
    
    try {
      authnRequest = new String(inflated, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new SAMLException("UTF-8 is missing, oh well.", e);
    }
    
    return parseAuthnRequest(authnRequest);
  }
  
  // [dew]
  public LogoutRequest validateLogoutRequest(String logoutRequest)
      throws SAMLException
  {
    byte[] decoded = DatatypeConverter.parseBase64Binary(logoutRequest);
    
    byte[] inflated;
    try {
      inflated = inflate(decoded);
    } catch (IOException e) {
      throw new SAMLException(e);
    } catch (DataFormatException e) {
      throw new SAMLException(e);
    }
    
    try {
      logoutRequest = new String(inflated, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new SAMLException("UTF-8 is missing, oh well.", e);
    }
    
    return parseLogoutRequest(logoutRequest);
  }
  
  // [dew]
  public String generateReponse(String inResponseTo, String sEntityId, String sACS, String sUsername) 
      throws Exception
  {
    Calendar calCurrent = Calendar.getInstance();
    calCurrent.add(Calendar.MINUTE, -2);
    Calendar calExpire = Calendar.getInstance();
    calExpire.add(Calendar.HOUR, 12);
    
    String dateTime  = SAMLUtils.formatISO8601_Z(calCurrent);
    String expire    = SAMLUtils.formatISO8601_Z(calExpire);
    
    String s = "";
    
    s += "<saml2p:Response ID=\"_" + System.currentTimeMillis() + "0\" InResponseTo=\"" + inResponseTo + "\" Destination=\"" + sACS + "\" IssueInstant=\"" + dateTime + "\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">";
    s += "<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + issuer + "</saml2:Issuer>";
    s += "<saml2p:Status>";
    s += "<saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>";
    s += "</saml2p:Status>";
    
    s += generateAssertion(inResponseTo, sEntityId, sACS, sUsername, dateTime, expire);
    
    s += "</saml2p:Response>";
    
    PrivateKey privateKey       = loadPrivateKey("private_key.pem");
    X509Certificate certificate = loadCertificate("public_key.crt");
    if(privateKey != null && certificate != null) {
      Response response = parseResponse(s);
      
      if(signResponse) {
        signResponse(response, privateKey, certificate);
      }
      
      try {
        return DatatypeConverter.printBase64Binary(toString(response).getBytes("UTF-8"));
      }
      catch (MarshallingException e) {
        throw new SAMLException(e);
      }
    }
    
    return DatatypeConverter.printBase64Binary(s.getBytes("UTF-8"));
  }
  
  public 
  String checkResponse(String authnResponse)
      throws SAMLException
  {
    byte[] decoded = DatatypeConverter.parseBase64Binary(authnResponse);
    try {
      authnResponse = new String(decoded, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new SAMLException("UTF-8 is missing, oh well.", e);
    }
    
    parseResponse(authnResponse);
    
    return authnResponse;
  }
  
  // [dew]
  public String generateAssertion(String inResponseTo, String sEntityId, String sACS, String sUsername, String dateTime, String expire) 
      throws Exception
  {
    String s = "";
    
    s += "<saml2:Assertion ID=\"_" + System.currentTimeMillis() + "1\" IssueInstant=\"" + dateTime + "\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">";
    
    // Issuer
    s += "<saml2:Issuer>" + issuer + "</saml2:Issuer>";
    
    // Subject
    s += "<saml2:Subject>";
    if(sUsername != null && sUsername.indexOf("@") > 0 && sUsername.indexOf('.') > 0) {
      s += "<saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress\" NameQualifier=\"" + sEntityId + "\" SPNameQualifier=\"" + sEntityId + "\">" + sUsername + "</saml2:NameID>";
    }
    else {
      s += "<saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" NameQualifier=\"" + sEntityId + "\" SPNameQualifier=\"" + sEntityId + "\">" + sUsername + "</saml2:NameID>";
    }
    s += "<saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">";
    s += "<saml2:SubjectConfirmationData InResponseTo=\"" + inResponseTo + "\" NotOnOrAfter=\"" + expire + "\" Recipient=\"" + sACS + "\"/></saml2:SubjectConfirmation>";
    s += "</saml2:Subject>";
    
    // Conditions
    s += "<saml2:Conditions NotBefore=\"" + dateTime + "\" NotOnOrAfter=\"" + expire + "\">";
    s += "<saml2:AudienceRestriction><saml2:Audience>" + sEntityId + "</saml2:Audience></saml2:AudienceRestriction>";
    s += "</saml2:Conditions>";
    
    // AuthnStatement
    s += "<saml2:AuthnStatement AuthnInstant=\"" + dateTime + "\" SessionIndex=\"_" + System.currentTimeMillis() + "\">";
    s += "<saml2:SubjectLocality Address=\"" + sEntityId + "\"/>";
    s += "<saml2:AuthnContext>";
    s += "<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>";
    s += "</saml2:AuthnContext>";
    s += "</saml2:AuthnStatement>";
    
    // AttributeStatement
    s += "<saml2:AttributeStatement>";
    
    s += "<saml2:Attribute Name=\"User.FirstName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">";
    s += "<saml2:AttributeValue>NA</saml2:AttributeValue>";
    s += "</saml2:Attribute>";
    s += "<saml2:Attribute Name=\"User.LastName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">";
    s += "<saml2:AttributeValue>NA</saml2:AttributeValue>";
    s += "</saml2:Attribute>";
    s += "<saml2:Attribute Name=\"memberOf\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">";
    s += "<saml2:AttributeValue></saml2:AttributeValue>";
    s += "</saml2:Attribute>";
    s += "<saml2:Attribute Name=\"PersonImmutableID\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">";
    s += "<saml2:AttributeValue></saml2:AttributeValue>";
    s += "</saml2:Attribute>";
    s += "<saml2:Attribute Name=\"User.email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">";
    if(sUsername != null && sUsername.indexOf("@") > 0 && sUsername.indexOf('.') > 0) {
      s += "<saml2:AttributeValue>" + sUsername + "</saml2:AttributeValue>";
    }
    else {
      s += "<saml2:AttributeValue></saml2:AttributeValue>";
    }
    s += "</saml2:Attribute>";
    
    if(extraAttributes) {
      s += "<saml2:Attribute FriendlyName=\"credentialType\" Name=\"credentialType\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">";
      s += "<saml2:AttributeValue>UsernamePasswordCredential</saml2:AttributeValue>";
      s += "</saml2:Attribute>";
      s += "<saml2:Attribute FriendlyName=\"samlAuthenticationStatementAuthMethod\" Name=\"samlAuthenticationStatementAuthMethod\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">";
      s += "<saml2:AttributeValue>urn:oasis:names:tc:SAML:1.0:am:password</saml2:AttributeValue>";
      s += "</saml2:Attribute>";
      s += "<saml2:Attribute FriendlyName=\"isFromNewLogin\" Name=\"isFromNewLogin\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">";
      s += "<saml2:AttributeValue>true</saml2:AttributeValue>";
      s += "</saml2:Attribute>";
      s += "<saml2:Attribute FriendlyName=\"authenticationDate\" Name=\"authenticationDate\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">";
      s += "<saml2:AttributeValue>" + dateTime + "</saml2:AttributeValue>";
      s += "</saml2:Attribute>";
      s += "<saml2:Attribute FriendlyName=\"authenticationMethod\" Name=\"authenticationMethod\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">";
      s += "<saml2:AttributeValue>LdapAuthenticationHandler</saml2:AttributeValue>";
      s += "</saml2:Attribute>";
      s += "<saml2:Attribute FriendlyName=\"successfulAuthenticationHandlers\" Name=\"successfulAuthenticationHandlers\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">";
      s += "<saml2:AttributeValue>LdapAuthenticationHandler</saml2:AttributeValue>";
      s += "</saml2:Attribute>";
      s += "<saml2:Attribute FriendlyName=\"longTermAuthenticationRequestTokenUsed\" Name=\"longTermAuthenticationRequestTokenUsed\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">";
      s += "<saml2:AttributeValue>false</saml2:AttributeValue>";
      s += "</saml2:Attribute>";
    }
    
    s += "</saml2:AttributeStatement>";
    
    s += "</saml2:Assertion>";
    
    if(signAssertion || encryptAssertion) {
      PrivateKey privateKey       = loadPrivateKey("private_key.pem");
      X509Certificate certificate = loadCertificate("public_key.crt");
      if(privateKey != null && certificate != null) {
        
        Assertion assertion = getAssertion(s);
        
        if(signAssertion) {
          signAssertion(assertion, privateKey, certificate);
        }
        
        if(encryptAssertion) {
          s = toString(encryptAssertion(assertion, certificate));
        }
        else {
          s = toString(assertion);
        }
      }
    }
    
    return s;
  }
  
  // [dew]
  private 
  byte[] inflate(byte[] input)
      throws IOException, DataFormatException
  {
    Inflater inflater = new Inflater(true);
    inflater.setInput(input);
    
    byte[] tmp = new byte[8192];
    int count;
    
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    while (!inflater.finished()) {
      count = inflater.inflate(tmp);
      bos.write(tmp, 0, count);
    }
    bos.close();
    inflater.end();
    
    return bos.toByteArray();
  }
  
  private 
  Response parseResponse(String authnResponse)
      throws SAMLException
  {
    try {
      Document doc = parsers.getBuilder()
          .parse(new InputSource(new StringReader(authnResponse)));
      
      Element root = doc.getDocumentElement();
      return (Response) Configuration.getUnmarshallerFactory()
          .getUnmarshaller(root)
          .unmarshall(root);
    }
    catch (org.opensaml.xml.parse.XMLParserException e) {
      throw new SAMLException(e);
    }
    catch (org.opensaml.xml.io.UnmarshallingException e) {
      throw new SAMLException(e);
    }
    catch (org.xml.sax.SAXException e) {
      throw new SAMLException(e);
    }
    catch (java.io.IOException e) {
      throw new SAMLException(e);
    }
  }
  
  // [dew]
  private AuthnRequest parseAuthnRequest(String authnResponse)
      throws SAMLException
  {
    try {
      Document doc = parsers.getBuilder()
          .parse(new InputSource(new StringReader(authnResponse)));
      
      Element root = doc.getDocumentElement();
      return (AuthnRequest) Configuration.getUnmarshallerFactory()
          .getUnmarshaller(root)
          .unmarshall(root);
    }
    catch (org.opensaml.xml.parse.XMLParserException e) {
      throw new SAMLException(e);
    }
    catch (org.opensaml.xml.io.UnmarshallingException e) {
      throw new SAMLException(e);
    }
    catch (org.xml.sax.SAXException e) {
      throw new SAMLException(e);
    }
    catch (java.io.IOException e) {
      throw new SAMLException(e);
    }
  }
  
  // [dew]
  private LogoutRequest parseLogoutRequest(String logoutRequest)
      throws SAMLException
  {
    try {
      Document doc = parsers.getBuilder()
          .parse(new InputSource(new StringReader(logoutRequest)));
      
      Element root = doc.getDocumentElement();
      return (LogoutRequest) Configuration.getUnmarshallerFactory()
          .getUnmarshaller(root)
          .unmarshall(root);
    }
    catch (org.opensaml.xml.parse.XMLParserException e) {
      throw new SAMLException(e);
    }
    catch (org.opensaml.xml.io.UnmarshallingException e) {
      throw new SAMLException(e);
    }
    catch (org.xml.sax.SAXException e) {
      throw new SAMLException(e);
    }
    catch (java.io.IOException e) {
      throw new SAMLException(e);
    }
  }
  
  // [dew]
  public static
  Assertion getAssertion(String assertion)
      throws Exception
  {
    if(assertion == null || assertion.length() == 0) return null;
    
    BasicParserPool basicParserPool = new BasicParserPool();
    basicParserPool.setNamespaceAware(true);
    
    Document document = basicParserPool.parse(new ByteArrayInputStream(assertion.getBytes()));
    Element  element  = document.getDocumentElement();
    
    UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
    
    return (Assertion) unmarshaller.unmarshall(element);
  }
  
  // [dew]
  public static
  String toString(SAMLObject samlObject)
      throws Exception
  {
    if(samlObject == null) return null;
    
    // samlobject to xml dom object
    Element elem = Configuration.getMarshallerFactory().getMarshaller(samlObject).marshall(samlObject);
    // and to a string...
    Document document = elem.getOwnerDocument();
    DOMImplementationLS domImplLS = (DOMImplementationLS) document.getImplementation();
    LSSerializer serializer = domImplLS.createLSSerializer();
    serializer.getDomConfig().setParameter("xml-declaration", false);
    
    return serializer.writeToString(elem);
  }
  
  // [dew]
  public static
  String signXmlAssertion(String sAssertion, PrivateKey privateKey, X509Certificate certificate)
      throws Exception
  {
    Assertion assertion = getAssertion(sAssertion);
    
    signAssertion(assertion, privateKey, certificate);
    
    return toString(assertion);
  }
  
  // [dew]
  public static
  void signAssertion(Assertion assertion, PrivateKey privateKey, X509Certificate certificate)
      throws Exception
  {
    BasicX509Credential signingCredential = new BasicX509Credential();
    signingCredential.setPrivateKey(privateKey);
    signingCredential.setEntityCertificate(certificate);
    
    KeyInfo keyInfo = null;
    try {
      X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
      x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
      keyInfo = x509KeyInfoGeneratorFactory.newInstance().generate(signingCredential);
    } 
    catch(Exception ex) {
      ex.printStackTrace();
    }
    
    Signature signature = (Signature) Configuration.getBuilderFactory()
        .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
        .buildObject(Signature.DEFAULT_ELEMENT_NAME);
    
    signature.setSigningCredential(signingCredential);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    signature.setKeyInfo(keyInfo);
    
    assertion.setSignature(signature);
    
    Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
    
    Signer.signObject(signature);
  }
  
  // [dew]
  public static
  void signResponse(Response response, PrivateKey privateKey, X509Certificate certificate)
      throws Exception
  {
    BasicX509Credential signingCredential = new BasicX509Credential();
    signingCredential.setPrivateKey(privateKey);
    signingCredential.setEntityCertificate(certificate);
    
    KeyInfo keyInfo = null;
    try {
      X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
      x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
      keyInfo = x509KeyInfoGeneratorFactory.newInstance().generate(signingCredential);
    } 
    catch(Exception ex) {
      ex.printStackTrace();
    }
    
    Signature signature = (Signature) Configuration.getBuilderFactory()
        .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
        .buildObject(Signature.DEFAULT_ELEMENT_NAME);
    
    signature.setSigningCredential(signingCredential);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    signature.setKeyInfo(keyInfo);
    
    response.setSignature(signature);
    
    Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
    
    Signer.signObject(signature);
  }
  
  // [dew]
  public static
  EncryptedAssertion encryptAssertion(Assertion assertion, X509Certificate certificate)
      throws Exception
  {
    BasicCredential encryptCredential = new BasicCredential();
    encryptCredential.setPublicKey(certificate.getPublicKey());
    
    EncryptionParameters encryptionParameters = new EncryptionParameters();
    encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
    
    KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
    keyEncryptionParameters.setEncryptionCredential(encryptCredential);
    keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
    
    KeyInfoGeneratorFactory keyInfoGeneratorFactory = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager().getDefaultManager().getFactory(encryptCredential);
    keyEncryptionParameters.setKeyInfoGenerator(keyInfoGeneratorFactory.newInstance());
    
    Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
    encrypter.setKeyPlacement(KeyPlacement.INLINE);
    return encrypter.encrypt(assertion);
  }
  
  // [dew]
  public static
  X509Certificate loadCertificate(String sFile)
      throws Exception
  {
    int iFileSep = sFile.indexOf('/');
    if(iFileSep < 0) iFileSep = sFile.indexOf('\\');
    InputStream is = null;
    if(iFileSep < 0) {
      URL url = Thread.currentThread().getContextClassLoader().getResource(sFile);
      is = url.openStream();
    }
    else {
      is = new FileInputStream(sFile);
    }
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      int n;
      byte[] buff = new byte[1024];
      while((n = is.read(buff)) > 0) baos.write(buff, 0, n);
    }
    finally {
      if(is != null) try{ is.close(); } catch(Exception ex) {}
    }
    byte[] content = baos.toByteArray();
    if(content == null || content.length < 4) {
      throw new Exception("Invalid file");
    }
    if(content[0] == 45 && content[1] == 45 && content[2] == 45) {
      String sContent = new String(content);
      int iStart = sContent.indexOf("ATE-----");
      if(iStart > 0) {
        int iEnd = sContent.indexOf("-----END");
        if(iEnd > 0) {
          String sBase64 = sContent.substring(iStart+8, iEnd).trim();
          content = Base64Coder.decodeLines(sBase64);
        }
      }
    }
    ByteArrayInputStream bais = new ByteArrayInputStream(content);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(bais);
  }
  
  // [dew]
  public static
  PrivateKey loadPrivateKey(String sFile)
      throws Exception
  {
    int iFileSep = sFile.indexOf('/');
    if(iFileSep < 0) iFileSep = sFile.indexOf('\\');
    InputStream is = null;
    if(iFileSep < 0) {
      URL url = Thread.currentThread().getContextClassLoader().getResource(sFile);
      is = url.openStream();
    }
    else {
      is = new FileInputStream(sFile);
    }
    PEMReader pemReader = null;
    try {
      Security.addProvider(new BouncyCastleProvider());
      
      pemReader = new PEMReader(new InputStreamReader(is));
      
      Object pemObject = pemReader.readObject();
      if(pemObject instanceof KeyPair) {
        return ((KeyPair) pemObject).getPrivate();
      }
      
      throw new Exception("Invalid pem file " + sFile);
    }
    finally {
      if(is != null) try{ is.close(); } catch(Exception ex) {}
      if(pemReader != null) try{ pemReader.close(); } catch(Exception ex) {}
    }
  }
}
