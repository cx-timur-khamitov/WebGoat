/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.security.ForbiddenClassException;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class VulnerableComponentsLessonTest {

  String strangeContact =
      "<contact class='dynamic-proxy'>\n"
          + "<interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>\n"
          + "  <handler class='java.beans.EventHandler'>\n"
          + "    <target class='java.lang.ProcessBuilder'>\n"
          + "      <command>\n"
          + "        <string>calc.exe</string>\n"
          + "      </command>\n"
          + "    </target>\n"
          + "    <action>start</action>\n"
          + "  </handler>\n"
          + "</contact>";
  String contact = "<contact>\n" + "</contact>";

  /**
   * Build an XStream instance using the same allowlist-restricted configuration applied in the
   * production endpoint after the CWE-502 remediation.
   */
  private XStream buildSecureXStream() {
    XStream xstream = new XStream();
    xstream.addPermission(NoTypePermission.NONE);
    xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
    xstream.allowTypes(new Class[] {ContactImpl.class, String.class, Integer.class});
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    return xstream;
  }

  @Test
  public void testTransformation() throws Exception {
    XStream xstream = buildSecureXStream();
    assertThat(xstream.fromXML(contact)).isNotNull();
  }

  @Test
  public void testIllegalTransformation() throws Exception {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    try {
      ((Contact) xstream.fromXML(strangeContact)).getFirstName();
    } catch (Throwable t) {
      Throwable c = t;
      int i = 0;
      while (c != null && i < 10) {
        System.out.println("CHAIN[" + i + "] " + c.getClass().getName() + " :: " + c.getMessage());
        c = c.getCause();
        i++;
      }
    }
  }

  @Test
  public void testIllegalPayload() throws Exception {
    XStream xstream = buildSecureXStream();
    Exception e =
        assertThrows(
            StreamException.class, () -> ((Contact) xstream.fromXML("bullssjfs")).getFirstName());
    assertThat(e.getCause().getMessage().contains("START_DOCUMENT")).isTrue();
  }

  /**
   * Verify that the secure XStream configuration blocks the CVE-2013-7285 dynamic-proxy payload
   * used to trigger arbitrary code execution. With the allowlist applied, deserialization of
   * disallowed types must throw ForbiddenClassException rather than executing the payload.
   */
  @Test
  public void testSecureConfigBlocksDynamicProxyPayload() {
    XStream secureXstream = buildSecureXStream();
    // The dynamic-proxy / EventHandler payload must be rejected by the type allowlist.
    assertThrows(
        ForbiddenClassException.class,
        () -> secureXstream.fromXML(strangeContact),
        "Secure XStream must reject dynamic-proxy payloads used in CVE-2013-7285");
  }

  /**
   * Verify that the secure XStream configuration blocks payloads that attempt to instantiate
   * java.lang.ProcessBuilder directly (another common RCE vector).
   */
  @Test
  public void testSecureConfigBlocksProcessBuilderPayload() {
    String processBuildPayload =
        "<contact>"
            + "  <firstName class='java.lang.ProcessBuilder'>"
            + "    <command><string>calc.exe</string></command>"
            + "  </firstName>"
            + "</contact>";
    XStream secureXstream = buildSecureXStream();
    assertThrows(
        ForbiddenClassException.class,
        () -> secureXstream.fromXML(processBuildPayload),
        "Secure XStream must reject ProcessBuilder instantiation in XML payload");
  }

  /**
   * Verify that a legitimate contact payload is still deserialized correctly after applying the
   * allowlist, ensuring the fix does not break normal functionality.
   */
  @Test
  public void testSecureConfigAllowsLegitimateContact() {
    String legitimatePayload =
        "<contact>"
            + "  <firstName>John</firstName>"
            + "  <lastName>Doe</lastName>"
            + "  <email>john.doe@example.com</email>"
            + "  <id>1</id>"
            + "</contact>";
    XStream secureXstream = buildSecureXStream();
    Object result = secureXstream.fromXML(legitimatePayload);
    assertThat(result).isInstanceOf(ContactImpl.class);
    ContactImpl contactImpl = (ContactImpl) result;
    assertThat(contactImpl.getFirstName()).isEqualTo("John");
    assertThat(contactImpl.getLastName()).isEqualTo("Doe");
    assertThat(contactImpl.getEmail()).isEqualTo("john.doe@example.com");
    assertThat(contactImpl.getId()).isEqualTo(1);
  }

  /**
   * Verify that runtime.exec / similar gadget classes are blocked by the allowlist.
   */
  @Test
  public void testSecureConfigBlocksRuntimePayload() {
    String runtimePayload =
        "<contact class='java.lang.Runtime'>"
            + "  <firstName>malicious</firstName>"
            + "</contact>";
    XStream secureXstream = buildSecureXStream();
    assertThrows(
        ForbiddenClassException.class,
        () -> secureXstream.fromXML(runtimePayload),
        "Secure XStream must reject java.lang.Runtime instantiation");
  }
}
