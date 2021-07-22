/*
 * SAMLClient - Main interface module for service providers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Copyright (c) 2014-2015 LastPass, Inc.
 */
package com.lastpass.saml;

import org.opensaml.Configuration;

import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Attribute;

import org.opensaml.saml2.encryption.Decrypter;

import org.opensaml.common.SAMLObjectBuilder;

import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.XMLObject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

import org.joda.time.DateTime;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import org.xml.sax.InputSource;

import java.io.StringReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;

import javax.xml.bind.DatatypeConverter;

/**
 * A SAMLClient acts as on behalf of a SAML Service
 * Provider to generate requests and process responses.
 *
 * To integrate a service, one must generally do the
 * following:
 *
 *  1. Change the login process to call
 *     generateAuthnRequest() to get a request and link,
 *     and then GET/POST that to the IdP login URL.
 *
 *  2. Create a new URL that acts as the
 *     AssertionConsumerService -- it will call
 *     validateResponse on the response body to
 *     verify the assertion; on success it will
 *     use the subject as the authenticated user for
 *     the web application.
 *
 * The specific changes needed to the application are
 * outside the scope of this SDK.
 */
@SuppressWarnings("deprecation")
public class SAMLClient
{
  private SPConfig spConfig;
  private IdPConfig idpConfig;
  private SignatureValidator sigValidator;
  private BasicParserPool parsers;
  private static SAMLClient _instance;
  
  /* do date comparisons +/- this many seconds */
  private static final int slack = (int) TimeUnit.MINUTES.toSeconds(5);
  
  /**
   * Create a new SAMLClient, using the IdPConfig for
   * endpoints and validation.
   */
  public SAMLClient(SPConfig spConfig, IdPConfig idpConfig)
      throws SAMLException
  {
    this.spConfig = spConfig;
    this.idpConfig = idpConfig;
    
    if(this.spConfig != null) {
      try {
        this.spConfig.setPrivateKey(loadPrivateKey("private_key.pem"));
      }
      catch(Exception ex) {
        ex.printStackTrace();
      }
    }
    
    BasicCredential cred = new BasicCredential();
    cred.setEntityId(idpConfig.getEntityId());
    cred.setPublicKey(idpConfig.getCert().getPublicKey());
    
    sigValidator = new SignatureValidator(cred);
    
    // create xml parsers
    parsers = new BasicParserPool();
    parsers.setNamespaceAware(true);
  }
  
  // [dew]
  public static SAMLClient getInstance()
      throws Exception
  {
    if(_instance != null) return _instance;
    SAMLInit.initialize();
    IdPConfig _idpConfig = new IdPConfig(Thread.currentThread().getContextClassLoader().getResourceAsStream("idp-metadata.xml"));
    SPConfig  _spConfig  = new SPConfig(Thread.currentThread().getContextClassLoader().getResourceAsStream("sp-metadata.xml"));
    _instance = new SAMLClient(_spConfig, _idpConfig);
    return _instance;
  }
  
  /**
   * Get the configured IdpConfig.
   *
   * @return the IdPConfig associated with this client
   */
  public IdPConfig getIdPConfig()
  {
    return idpConfig;
  }
  
  /**
   * Get the configured SPConfig.
   *
   * @return the SPConfig associated with this client
   */
  public SPConfig getSPConfig()
  {
    return spConfig;
  }
  
  private Response parseResponse(String authnResponse)
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
  
  /**
   * Decrypt an assertion using the privkey stored in SPConfig.
   */
  private Assertion decrypt(EncryptedAssertion encrypted)
      throws DecryptionException
  {
    if (spConfig.getPrivateKey() == null)
      throw new DecryptionException("Encrypted assertion found but no SP key available");
    BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(spConfig.getPrivateKey());
    StaticKeyInfoCredentialResolver resolver =
        new StaticKeyInfoCredentialResolver(cred);
    Decrypter decrypter =
        new Decrypter(null, resolver, new InlineEncryptedKeyResolver());
    decrypter.setRootInNewDocument(true);
    
    return decrypter.decrypt(encrypted);
  }
  
  /**
   * Retrieve all supplied assertions, decrypting any encrypted
   * assertions if necessary.
   */
  private List<Assertion> getAssertions(Response response)
      throws DecryptionException
  {
    List<Assertion> assertions = new ArrayList<Assertion>();
    assertions.addAll(response.getAssertions());
    
    for (EncryptedAssertion e : response.getEncryptedAssertions()) {
      assertions.add(decrypt(e));
    }
    
    return assertions;
  }
  
  private void validate(Response response)
      throws ValidationException
  {
    // response signature must match IdP's key, if present
    Signature sig = response.getSignature();
    if (sig != null)
      sigValidator.validate(sig);
    
    // response must be successful
    if (response.getStatus() == null ||
        response.getStatus().getStatusCode() == null ||
        !(StatusCode.SUCCESS_URI
            .equals(response.getStatus().getStatusCode().getValue()))) {
      throw new ValidationException(
          "Response has an unsuccessful status code");
    }
    
    // [dew]
    // response destination must match ACS
    //        if (!spConfig.getAcs().equals(response.getDestination()))
    //            throw new ValidationException(
    //                "Response is destined for a different endpoint");
    
    DateTime now = DateTime.now();
    
    // issue instant must be within a day
    DateTime issueInstant = response.getIssueInstant();
    
    if (issueInstant != null) {
      if (issueInstant.isBefore(now.minusSeconds(24 * 60 * 60)))
        throw new ValidationException("Response IssueInstant (" + issueInstant + ") is in the past (" + now.minusSeconds(24 * 60 * 60) + ")");
      
      if (issueInstant.isAfter(now.plusSeconds(24 * 60 * 60)))
        throw new ValidationException("Response IssueInstant (" + issueInstant + ") is in the future (" + now.plusSeconds(24 * 60 * 60) + ")");
    }
    
    List<Assertion> assertions = null;
    try {
      assertions = getAssertions(response);
    } catch (DecryptionException e) {
      throw new ValidationException(e);
    }
    
    for (Assertion assertion: assertions) {
      
      // [dew]
      // Assertion must be signed correctly
      //            if (!assertion.isSigned())
      //                throw new ValidationException(
      //                    "Assertion must be signed");
      //
      //            sig = assertion.getSignature();
      //            sigValidator.validate(sig);
      
      // Assertion must contain an authnstatement
      // with an unexpired session
      if (assertion.getAuthnStatements().isEmpty()) {
        throw new ValidationException("Assertion should contain an AuthnStatement");
      }
      for (AuthnStatement as: assertion.getAuthnStatements()) {
        DateTime sessionTime = as.getSessionNotOnOrAfter();
        if (sessionTime != null) {
          DateTime exp = sessionTime.plusSeconds(slack);
          if (exp != null &&
              (now.isEqual(exp) || now.isAfter(exp)))
            throw new ValidationException("AuthnStatement has expired");
        }
      }
      
      if (assertion.getConditions() == null) {
        throw new ValidationException("Assertion should contain conditions");
      }
      
      // Assertion IssueInstant must be within a day
      DateTime instant = assertion.getIssueInstant();
      if (instant != null) {
        if (instant.isBefore(now.minusSeconds(slack)))
          throw new ValidationException("Response IssueInstant is in the past");
        
        if (instant.isAfter(now.plusSeconds(slack)))
          throw new ValidationException("Response IssueInstant is in the future");
      }
      
      // Conditions must be met by current time
      Conditions conditions = assertion.getConditions();
      DateTime notBefore = conditions.getNotBefore();
      DateTime notOnOrAfter = conditions.getNotOnOrAfter();
      
      if (notBefore == null || notOnOrAfter == null)
        throw new ValidationException("Assertion conditions must have limits");
      
      notBefore = notBefore.minusSeconds(slack);
      notOnOrAfter = notOnOrAfter.plusSeconds(slack);
      
      if (now.isBefore(notBefore))
        throw new ValidationException("Assertion conditions is in the future");
      
      if (now.isEqual(notOnOrAfter) || now.isAfter(notOnOrAfter))
        throw new ValidationException("Assertion conditions is in the past");
      
      // If subjectConfirmationData is included, it must
      // have a recipient that matches ACS, with a valid
      // NotOnOrAfter
      Subject subject = assertion.getSubject();
      if (subject != null &&
          !subject.getSubjectConfirmations().isEmpty()) {
        boolean foundRecipient = false;
        for (SubjectConfirmation sc: subject.getSubjectConfirmations()) {
          if (sc.getSubjectConfirmationData() == null)
            continue;
          
          SubjectConfirmationData scd = sc.getSubjectConfirmationData();
          if (scd.getNotOnOrAfter() != null) {
            DateTime chkdate = scd.getNotOnOrAfter().plusSeconds(slack);
            if (now.isEqual(chkdate) || now.isAfter(chkdate)) {
              throw new ValidationException("SubjectConfirmationData is in the past");
            }
          }
          // [dew]
          foundRecipient = scd.getRecipient() != null;
          //                    if (spConfig.getAcs().equals(scd.getRecipient()))
          //                        foundRecipient = true;
        }
        
        if (!foundRecipient)
          throw new ValidationException("No SubjectConfirmationData found for ACS");
      }
      
      // audience must include intended SP issuer
      if (conditions.getAudienceRestrictions().isEmpty())
        throw new ValidationException("Assertion conditions must have audience restrictions");
      
      // only one audience restriction supported: we can only
      // check against the single SP.
      if (conditions.getAudienceRestrictions().size() > 1)
        throw new ValidationException("Assertion contains multiple audience restrictions");
      
      AudienceRestriction ar = conditions.getAudienceRestrictions().get(0);
      
      // at least one of the audiences must match our SP
      boolean foundSP = false;
      for (Audience a: ar.getAudiences()) {
        if (spConfig.getEntityId().equals(a.getAudienceURI()))
          foundSP = true;
      }
      if (!foundSP)
        throw new ValidationException("Assertion audience does not include issuer");
    }
  }
  
  @SuppressWarnings("unchecked")
  private String createAuthnRequest(String requestId)
      throws SAMLException
  {
    XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
    
    SAMLObjectBuilder<AuthnRequest> builder =
        (SAMLObjectBuilder<AuthnRequest>) builderFactory
        .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
    
    SAMLObjectBuilder<Issuer> issuerBuilder =
        (SAMLObjectBuilder<Issuer>) builderFactory
        .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
    
    AuthnRequest request = builder.buildObject();
    request.setAssertionConsumerServiceURL(spConfig.getAcs().toString());
    request.setDestination(idpConfig.getLoginUrl().toString());
    request.setIssueInstant(new DateTime());
    request.setID(requestId);
    
    Issuer issuer = issuerBuilder.buildObject();
    issuer.setValue(spConfig.getEntityId());
    request.setIssuer(issuer);
    
    try {
      // samlobject to xml dom object
      Element elem = Configuration.getMarshallerFactory()
          .getMarshaller(request)
          .marshall(request);
      
      // and to a string...
      Document document = elem.getOwnerDocument();
      DOMImplementationLS domImplLS = (DOMImplementationLS) document
          .getImplementation();
      LSSerializer serializer = domImplLS.createLSSerializer();
      serializer.getDomConfig().setParameter("xml-declaration", false);
      return serializer.writeToString(elem);
    }
    catch (MarshallingException e) {
      throw new SAMLException(e);
    }
  }
  
  private byte[] deflate(byte[] input)
      throws IOException
  {
    Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
    deflater.setInput(input);
    deflater.finish();
    
    byte[] tmp = new byte[8192];
    int count;
    
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    while (!deflater.finished()) {
      count = deflater.deflate(tmp);
      bos.write(tmp, 0, count);
    }
    bos.close();
    deflater.end();
    
    return bos.toByteArray();
  }
  
  /**
   * Create a new AuthnRequest suitable for sending to an HTTPRedirect
   * binding endpoint on the IdP.  The SPConfig will be used to fill
   * in the ACS and issuer, and the IdP will be used to set the
   * destination.
   *
   * @return a deflated, base64-encoded AuthnRequest
   */
  public String generateAuthnRequest(String requestId)
      throws SAMLException
  {
    String request = createAuthnRequest(requestId);
    
    try {
      byte[] compressed = deflate(request.getBytes("UTF-8"));
      return DatatypeConverter.printBase64Binary(compressed);
    } catch (UnsupportedEncodingException e) {
      throw new SAMLException("Apparently your platform lacks UTF-8.  That's too bad.", e);
    } catch (IOException e) {
      throw new SAMLException("Unable to compress the AuthnRequest", e);
    }
  }
  
  /**
   * Check an authnResponse and return the subject if validation
   * succeeds.  The NameID from the subject in the first valid
   * assertion is returned along with the attributes.
   *
   * @param authnResponse a base64-encoded AuthnResponse from the SP
   * @throws SAMLException if validation failed.
   * @return the authenticated subject/attributes as an AttributeSet
   */
  public AttributeSet validateResponse(String authnResponse)
      throws SAMLException
  {
    byte[] decoded = DatatypeConverter.parseBase64Binary(authnResponse);
    try {
      authnResponse = new String(decoded, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new SAMLException("UTF-8 is missing, oh well.", e);
    }
    
    Response response = parseResponse(authnResponse);
    
    try {
      validate(response);
    } catch (ValidationException e) {
      throw new SAMLException(e);
    }
    
    List<Assertion> assertions = null;
    try {
      assertions = getAssertions(response);
    } catch (DecryptionException e) {
      throw new SAMLException(e);
    }
    
    // we only look at first assertion
    if (assertions.size() != 1) {
      throw new SAMLException("Response should have a single assertion.");
    }
    Assertion assertion = assertions.get(0);
    
    Subject subject = assertion.getSubject();
    if (subject == null) {
      throw new SAMLException("No subject contained in the assertion.");
    }
    if (subject.getNameID() == null) {
      throw new SAMLException("No NameID found in the subject.");
    }
    
    String nameId = subject.getNameID().getValue();
    
    HashMap<String, List<String>> attributes =
        new HashMap<String, List<String>>();
    
    for (AttributeStatement atbs : assertion.getAttributeStatements()) {
      for (Attribute atb: atbs.getAttributes()) {
        String name = atb.getName();
        List<String> values = new ArrayList<String>();
        for (XMLObject obj : atb.getAttributeValues()) {
          values.add(obj.getDOM().getTextContent());
        }
        attributes.put(name, values);
      }
    }
    
    // [dew]
    return new AttributeSet(nameId, response.getInResponseTo(), attributes);
  }
  
  // [dew]
  public String getRedirectURL() {
    String sResult = null;
    try {
      String requestId = SAMLUtils.generateRequestId();
      
      String authRequest = generateAuthnRequest(requestId);
      
      sResult = getIdPConfig().getLoginUrl() + "?SAMLRequest=" + URLEncoder.encode(authRequest, "UTF-8");
    }
    catch(Exception ex) {
      ex.printStackTrace();
    }
    return sResult;
  }
  
  // [dew]
  public String getRedirectURL(String relayState) {
    String sResult = null;
    try {
      String requestId = SAMLUtils.generateRequestId();
      
      String authRequest = generateAuthnRequest(requestId);
      
      if(relayState != null && relayState.length() > 0) {
        sResult = getIdPConfig().getLoginUrl() + "?SAMLRequest=" + URLEncoder.encode(authRequest, "UTF-8") + "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");
      }
      else {
        sResult = getIdPConfig().getLoginUrl() + "?SAMLRequest=" + URLEncoder.encode(authRequest, "UTF-8");
      }
    }
    catch(Exception ex) {
      ex.printStackTrace();
    }
    return sResult;
  }
  
  // [dew]
  public String base64Decode(String sB64) {
    if(sB64 == null || sB64.length() == 0) return "";
    String sResult = "";
    try {
      sResult = new String(DatatypeConverter.parseBase64Binary(sB64), "UTF-8");
    } 
    catch (Exception ex) {
      return ex.toString();
    }
    return sResult;
  }
  
  // [dew]
  public String getRedirectLogoutURL(String loginRequestId) {
    String sResult = null;
    try {
      String requestId = SAMLUtils.generateRequestId();
      
      String logoutRequest = generateLogoutRequest(requestId, loginRequestId);
      
      sResult = getIdPConfig().getLogoutUrl() + "?SAMLRequest=" + URLEncoder.encode(logoutRequest, "UTF-8");
    }
    catch(Exception ex) {
      ex.printStackTrace();
    }
    return sResult;
  }
  
  // [dew]
  @SuppressWarnings("unchecked")
  private String createLogoutRequest(String requestId, String loginRequestId)
      throws SAMLException
  {
    XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
    
    SAMLObjectBuilder<LogoutRequest> builder =
        (SAMLObjectBuilder<LogoutRequest>) builderFactory
        .getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
    
    SAMLObjectBuilder<Issuer> issuerBuilder =
        (SAMLObjectBuilder<Issuer>) builderFactory
        .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
    
    SAMLObjectBuilder<NameID> nameIdBuilder =
        (SAMLObjectBuilder<NameID>) builderFactory
        .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
    
    LogoutRequest request = builder.buildObject();
    request.setDestination(idpConfig.getLoginUrl().toString());
    request.setIssueInstant(new DateTime());
    request.setID(requestId);
    
    Issuer issuer = issuerBuilder.buildObject();
    issuer.setValue(spConfig.getEntityId());
    request.setIssuer(issuer);
    
    NameID nameId = nameIdBuilder.buildObject();
    nameId.setSPNameQualifier(spConfig.getEntityId());
    nameId.setValue(loginRequestId);
    request.setNameID(nameId);
    
    try {
      PrivateKey      privateKey  = loadPrivateKey("private_key.pem");
      X509Certificate certificate = loadCertificate("public_key.crt");
      
      signLogoutRequest(request, privateKey, certificate);
      
      // samlobject to xml dom object
      Element elem = Configuration.getMarshallerFactory()
          .getMarshaller(request)
          .marshall(request);
      
      // and to a string...
      Document document = elem.getOwnerDocument();
      DOMImplementationLS domImplLS = (DOMImplementationLS) document
          .getImplementation();
      LSSerializer serializer = domImplLS.createLSSerializer();
      serializer.getDomConfig().setParameter("xml-declaration", false);
      return serializer.writeToString(elem);
    }
    catch (MarshallingException e) {
      throw new SAMLException(e);
    }
    catch (Exception e) {
      throw new SAMLException(e);
    }
  }
  
  /**
   * Create a new LogoutRequest suitable for sending to an HTTPRedirect
   * binding endpoint on the IdP.
   *
   * @return a deflated, base64-encoded LogoutRequest
   */
  // [dew]
  public String generateLogoutRequest(String requestId, String loginRequestId)
      throws SAMLException
  {
    String request = createLogoutRequest(requestId, loginRequestId);
    
    try {
      byte[] compressed = deflate(request.getBytes("UTF-8"));
      return DatatypeConverter.printBase64Binary(compressed);
    } catch (UnsupportedEncodingException e) {
      throw new SAMLException(
          "Apparently your platform lacks UTF-8.  That's too bad.", e);
    } catch (IOException e) {
      throw new SAMLException("Unable to compress the LogoutRequest", e);
    }
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
  
  // [dew]
  public static
  void signLogoutRequest(LogoutRequest logoutRequest, PrivateKey privateKey, X509Certificate certificate)
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
    
    logoutRequest.setSignature(signature);
    
    Configuration.getMarshallerFactory().getMarshaller(logoutRequest).marshall(logoutRequest);
    
    Signer.signObject(signature);
  }
}
