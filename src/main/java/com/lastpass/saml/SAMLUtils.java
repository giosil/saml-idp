/*
 * SAMLUtils - Utility functions
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
 * Copyright (c) 2014 LastPass, Inc.
 */
package com.lastpass.saml;

import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;

public 
class SAMLUtils
{
  private static final char[] hexes = "0123456789abcdef".toCharArray();
  
  private static 
  String hexEncode(byte[] b)
  {
    char[] out = new char[b.length * 2];
    for (int i = 0; i < b.length; i++)
    {
      out[i*2] = hexes[(b[i] >> 4) & 0xf];
      out[i*2 + 1] = hexes[b[i] & 0xf];
    }
    return new String(out);
  }
  
  /**
   *  Generate a request ID suitable for passing to
   *  SAMLClient.createAuthnRequest.
   */
  public static 
  String generateRequestId()
  {
    /* compute a random 256-bit string and hex-encode it */
    SecureRandom sr = new SecureRandom();
    byte[] bytes = new byte[32];
    sr.nextBytes(bytes);
    return "_" + hexEncode(bytes);
  }
  
  public static 
  String normalizeString(String sValue) 
  {
    if(sValue == null) return "null";
    int iLength = sValue.length();
    if(iLength == 0) return "";
    StringBuffer sb = new StringBuffer(iLength);
    for(int i = 0; i < iLength; i++) {
      char c = sValue.charAt(i);
      if(c == '<')  sb.append("&lt;");
      else if(c == '>')  sb.append("&gt;");
      else if(c == '&')  sb.append("&amp;");
      else if(c == '"')  sb.append("&quot;");
      else if(c == '\'') sb.append("&apos;");
      else if(c > 127) {
        int code = (int) c;
        sb.append("&#" + code + ";");
      }
      else {
        sb.append(c);
      }
    }
    return sb.toString();
  }
  
  public static 
  String formatISO8601_Z(Date date) {
    if(date == null) return "";
    Calendar cal = Calendar.getInstance();
    cal.setTimeInMillis(date.getTime());
    return formatISO8601_Z(cal, true);
  }
  
  public static 
  String formatISO8601_Z(Date date, boolean millis) {
    if(date == null) return "";
    Calendar cal = Calendar.getInstance();
    cal.setTimeInMillis(date.getTime());
    return formatISO8601_Z(cal, millis);
  }
  
  public static 
  String formatISO8601_Z(Calendar cal) {
    return formatISO8601_Z(cal, true);
  }
  
  public static 
  String formatISO8601_Z(Calendar cal, boolean millis) {
    if(cal == null) return "";
    
    int iZoneOffset = cal.get(Calendar.ZONE_OFFSET);
    cal.add(Calendar.MILLISECOND, -iZoneOffset);
    int iDST_Offset = cal.get(Calendar.DST_OFFSET);
    cal.add(Calendar.MILLISECOND, -iDST_Offset);
    
    int iYear  = cal.get(Calendar.YEAR);
    int iMonth = cal.get(Calendar.MONTH) + 1;
    int iDay   = cal.get(Calendar.DATE);
    int iHour  = cal.get(Calendar.HOUR_OF_DAY);
    int iMin   = cal.get(Calendar.MINUTE);
    int iSec   = cal.get(Calendar.SECOND);
    int iMill  = cal.get(Calendar.MILLISECOND);
    String sYear   = String.valueOf(iYear);
    String sMonth  = iMonth < 10 ? "0" + iMonth : String.valueOf(iMonth);
    String sDay    = iDay   < 10 ? "0" + iDay   : String.valueOf(iDay);
    String sHour   = iHour  < 10 ? "0" + iHour  : String.valueOf(iHour);
    String sMin    = iMin   < 10 ? "0" + iMin   : String.valueOf(iMin);
    String sSec    = iSec   < 10 ? "0" + iSec   : String.valueOf(iSec);
    String sMill   = String.valueOf(iMill);
    if(iYear < 10) {
      sYear = "000" + sYear;
    }
    else if(iYear < 100) {
      sYear = "00" + sYear;
    }
    else if(iYear < 1000) {
      sYear = "0" + sYear;
    }
    if(iMill < 10) {
      sMill = "00" + sMill; 
    }
    else if(iMill < 100) {
      sMill = "0" + sMill; 
    }
    if(millis) {
      return sYear + "-" + sMonth + "-" + sDay + "T" + sHour + ":" + sMin + ":" + sSec + "." + sMill + "Z";
    }
    return sYear + "-" + sMonth + "-" + sDay + "T" + sHour + ":" + sMin + ":" + sSec + "Z";
  }
  
  public static 
  String replaceHost(String url, String host) {
    if(host == null || host.length() == 0) {
      return url;
    }
    int sepCtx = url.indexOf('/', 8);
    if(sepCtx < 0) return url;
    int sepCtxHost = host.indexOf('/', 8);
    if(sepCtxHost > 0) {
      host = host.substring(0, sepCtxHost);
    }
    if(host.startsWith("http://") || host.startsWith("https://")) {
      return host + url.substring(sepCtx);
    }
    if(url.startsWith("https://")) {
      return "https://" + host + url.substring(sepCtx);
    }
    return "http://" + host + url.substring(sepCtx);
  }
  
  public static
  String escapeHtml(String text)
  {
    if(text == null) return "";
    int iLength = text.length();
    if(iLength == 0) return "";
    StringBuffer sb = new StringBuffer(iLength);
    for(int i = 0; i < iLength; i++) {
      char c = text.charAt(i);
      if(c == '<')  sb.append("&lt;");   else
      if(c == '>')  sb.append("&gt;");   else
      if(c == '&')  sb.append("&amp;");  else
      if(c == '"')  sb.append("&quot;"); else
      if(c == '\'') sb.append("&apos;"); else
      if(c > 127) {
        int code = (int) c;
        sb.append("&#" + code + ";");
      }
      else {
        sb.append(c);
      }
    }
    return sb.toString();
  }
}
