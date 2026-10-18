/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class ProfileZipSlipTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  // -----------------------------------------------------------------------
  // Unit tests for cleanupAndCreateDirectoryForUser path-traversal protection
  // -----------------------------------------------------------------------

  /**
   * Verifies that a legitimate username creates a directory strictly inside the
   * /PathTraversal/ base directory.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_normalUsername_createsDirectoryInsideBase(
      @TempDir Path tempDir) throws Exception {
    ProfileUploadBase base = new ProfileZipSlip(tempDir.toString());
    File result = base.cleanupAndCreateDirectoryForUser("alice");

    Path expected = tempDir.resolve("PathTraversal").resolve("alice").normalize();
    assertThat(result.toPath().normalize()).isEqualTo(expected);
    assertThat(result).isDirectory();
  }

  /**
   * Verifies that a username containing a relative path traversal sequence ("../")
   * is rejected with a SecurityException — the resolved path would escape the base.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_usernameWithDotDot_throwsSecurityException(
      @TempDir Path tempDir) {
    ProfileUploadBase base = new ProfileZipSlip(tempDir.toString());
    assertThatThrownBy(() -> base.cleanupAndCreateDirectoryForUser("../malicious"))
        .isInstanceOf(SecurityException.class);
  }

  /**
   * Verifies that a username with multiple traversal segments is also rejected.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_usernameWithMultipleDotDot_throwsSecurityException(
      @TempDir Path tempDir) {
    ProfileUploadBase base = new ProfileZipSlip(tempDir.toString());
    assertThatThrownBy(() -> base.cleanupAndCreateDirectoryForUser("../../etc/passwd"))
        .isInstanceOf(SecurityException.class);
  }

  /**
   * Verifies that an absolute path username is rejected (would escape the base on most systems).
   */
  @Test
  void cleanupAndCreateDirectoryForUser_absolutePathUsername_throwsSecurityException(
      @TempDir Path tempDir) {
    ProfileUploadBase base = new ProfileZipSlip(tempDir.toString());
    // An absolute path supplied as username resolves outside the base directory
    assertThatThrownBy(() -> base.cleanupAndCreateDirectoryForUser("/etc/passwd"))
        .isInstanceOf(SecurityException.class);
  }

  // -----------------------------------------------------------------------
  // Integration tests via MockMvc for the zip-slip upload endpoint
  // -----------------------------------------------------------------------

  /**
   * Uploading a non-zip file should return a failure response.
   */
  @Test
  void uploadZipSlip_withNonZipFile_returnsFeedbackNoZip() throws Exception {
    var file =
        new MockMultipartFile(
            "uploadedFileZipSlip", "image.jpg", "image/jpeg", "not a zip".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(file))
        .andExpect(status().is(200))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.containsString("path-traversal-zip-slip.no-zip")));
  }

  /**
   * Uploading a valid zip containing a normal file (no traversal) should succeed
   * and not throw an exception.
   */
  @Test
  void uploadZipSlip_withNormalZip_returns200() throws Exception {
    byte[] zipBytes = createZip("profile.jpg", "fake image content".getBytes());
    var file =
        new MockMultipartFile(
            "uploadedFileZipSlip", "upload.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(file))
        .andExpect(status().is(200));
  }

  // -----------------------------------------------------------------------
  // Helper
  // -----------------------------------------------------------------------

  /** Creates an in-memory ZIP archive with a single entry. */
  private static byte[] createZip(String entryName, byte[] entryContent) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      ZipEntry entry = new ZipEntry(entryName);
      zos.putNextEntry(entry);
      zos.write(entryContent);
      zos.closeEntry();
    }
    return baos.toByteArray();
  }
}
