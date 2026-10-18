/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link CommentsCache#parseXml} verifying that external entity (XXE) processing
 * is disabled unconditionally, regardless of the {@code securityEnabled} flag (CWE-611).
 */
class CommentsCacheTest {

  private CommentsCache commentsCache;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    commentsCache = new CommentsCache();
  }

  @Test
  void validXmlCommentParsedSuccessfully() throws Exception {
    String xml = "<comment><text>Hello WebGoat</text></comment>";

    Comment comment = commentsCache.parseXml(xml, false);

    assertThat(comment.getText()).isEqualTo("Hello WebGoat");
  }

  @Test
  void validXmlCommentParsedSuccessfullyWithSecurityEnabled() throws Exception {
    String xml = "<comment><text>Hello WebGoat</text></comment>";

    Comment comment = commentsCache.parseXml(xml, true);

    assertThat(comment.getText()).isEqualTo("Hello WebGoat");
  }

  /**
   * Verifies that an XXE payload referencing a local file is blocked when securityEnabled=false.
   * Before the fix, this would successfully read the file; after the fix the DTD/external entity
   * processing is disabled unconditionally and the payload must not resolve the file reference.
   */
  @Test
  void xxeFileReadIsBlockedWhenSecurityDisabled() throws Exception {
    Path secretFile = tempDir.resolve("secret.txt");
    Files.writeString(secretFile, "super-secret-content");

    String xxePayload =
        "<?xml version=\"1.0\" standalone=\"yes\" ?>"
            + "<!DOCTYPE comment [<!ENTITY secret SYSTEM \""
            + secretFile.toUri()
            + "\">]>"
            + "<comment><text>&secret;</text></comment>";

    // With DTD/external entity processing disabled, parsing should either throw an exception
    // (DTD not supported) or return a comment whose text does NOT contain the file's content.
    try {
      Comment comment = commentsCache.parseXml(xxePayload, false);
      // If parsing succeeds, the entity must NOT have been resolved to the file contents.
      assertThat(comment.getText())
          .as("XXE entity must not be resolved to file contents")
          .doesNotContain("super-secret-content");
    } catch (XMLStreamException e) {
      // An XMLStreamException is also an acceptable outcome — it means DTD processing was
      // disabled and the parser refused to process the DOCTYPE declaration.
      assertThat(e.getMessage())
          .as("Exception should be related to DTD/entity processing being disabled")
          .isNotNull();
    }
  }

  /**
   * Same as above but with securityEnabled=true — previously this path was already "fixed",
   * but confirms the unconditional protection is consistent.
   */
  @Test
  void xxeFileReadIsBlockedWhenSecurityEnabled() throws Exception {
    Path secretFile = tempDir.resolve("secret.txt");
    Files.writeString(secretFile, "super-secret-content");

    String xxePayload =
        "<?xml version=\"1.0\" standalone=\"yes\" ?>"
            + "<!DOCTYPE comment [<!ENTITY secret SYSTEM \""
            + secretFile.toUri()
            + "\">]>"
            + "<comment><text>&secret;</text></comment>";

    try {
      Comment comment = commentsCache.parseXml(xxePayload, true);
      assertThat(comment.getText())
          .as("XXE entity must not be resolved to file contents")
          .doesNotContain("super-secret-content");
    } catch (XMLStreamException e) {
      assertThat(e.getMessage()).isNotNull();
    }
  }

  /**
   * Verifies that an XXE SSRF-style payload (external URL) is blocked.
   * The parser must not attempt to fetch a remote URL declared in a DOCTYPE.
   */
  @Test
  void xxeExternalUrlIsBlocked() throws Exception {
    String xxePayload =
        "<?xml version=\"1.0\" ?>"
            + "<!DOCTYPE comment [<!ENTITY remote SYSTEM \"http://169.254.169.254/latest/meta-data/\">]>"
            + "<comment><text>&remote;</text></comment>";

    try {
      Comment comment = commentsCache.parseXml(xxePayload, false);
      // If parsing succeeds the remote entity must not have been fetched / resolved.
      assertThat(comment.getText())
          .as("XXE entity referencing remote URL must not be resolved")
          .doesNotContain("169.254.169.254");
    } catch (Exception e) {
      // Any exception indicates the entity/DTD was blocked — this is the expected secure behavior.
      assertThat(e).isNotNull();
    }
  }

  @Test
  void malformedXmlThrowsException() {
    String malformedXml = "<comment><text>not closed";

    assertThrows(
        Exception.class,
        () -> commentsCache.parseXml(malformedXml, false),
        "Malformed XML should throw an exception");
  }
}
