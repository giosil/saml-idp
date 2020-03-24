package org.dew.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class TestSAMLIDP extends TestCase {
  
  public TestSAMLIDP(String testName) {
    super(testName);
  }
  
  public static Test suite() {
    return new TestSuite(TestSAMLIDP.class);
  }
  
  public void testApp() throws Exception {
    System.out.println("org.dew.test.TestSAMLIDP");
  }
}
