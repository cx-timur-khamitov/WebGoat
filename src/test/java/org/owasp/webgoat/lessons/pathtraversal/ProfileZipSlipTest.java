/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

  /**
   * Creates a ZIP file in memory with a single entry whose name can be attacker-controlled.
   */
  private byte[] createZipWithEntry(String entryName, byte[] content) throws IOException {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos)) {
      ZipEntry entry = new ZipEntry(entryName);
      zos.putNextEntry(entry);
      zos.write(content);
      zos.closeEntry();
      return baos.toByteArray();
    }
  }

  // -------------------------------------------------------------------------
  // Security regression tests: path traversal attempts must be blocked
  // -------------------------------------------------------------------------

  /**
   * Classic Zip Slip: entry name starts with multiple "../" sequences.
   * After the fix the upload must be rejected (lessonCompleted=false, no traversal).
   */
  @Test
  void zipSlipWithLeadingDotDotShouldBeRejected() throws Exception {
    byte[] zipBytes = createZipWithEntry(
        "../../../../../../tmp/evil.sh",
        "evil content".getBytes(StandardCharsets.UTF_8));

    MockMultipartFile zipFile = new MockMultipartFile(
        "uploadedFileZipSlip", "attack.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Absolute-path Zip Slip: entry name is an absolute path starting with "/".
   * The fix must prevent this from escaping the temp directory.
   */
  @Test
  void zipSlipWithAbsolutePathEntryShouldBeRejected() throws Exception {
    byte[] zipBytes = createZipWithEntry(
        "/etc/cron.d/evil",
        "* * * * * root rm -rf /".getBytes(StandardCharsets.UTF_8));

    MockMultipartFile zipFile = new MockMultipartFile(
        "uploadedFileZipSlip", "attack.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Relative path that stays inside the temp directory must still be extracted normally
   * (the fix must not break legitimate ZIP uploads).
   */
  @Test
  void legitimateZipUploadWithSafeEntryNameShouldBeProcessed() throws Exception {
    byte[] zipBytes = createZipWithEntry(
        "profile-image.jpg",
        "fake image data".getBytes(StandardCharsets.UTF_8));

    MockMultipartFile zipFile = new MockMultipartFile(
        "uploadedFileZipSlip", "profile.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200));
    // We don't assert lessonCompleted here because solving requires the image to match
    // the profile picture filename; the important thing is that a safe entry is not rejected.
  }

  /**
   * Non-ZIP file must be rejected with the appropriate error feedback.
   */
  @Test
  void nonZipFileShouldBeRejected() throws Exception {
    MockMultipartFile notAZip = new MockMultipartFile(
        "uploadedFileZipSlip", "image.jpg", "image/jpeg",
        "not a zip".getBytes(StandardCharsets.UTF_8));

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(notAZip))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Zip Slip using Windows-style backslash path separator — must also be blocked.
   */
  @Test
  void zipSlipWithWindowsStylePathShouldBeRejected() throws Exception {
    byte[] zipBytes = createZipWithEntry(
        "..\\..\\..\\Windows\\System32\\evil.dll",
        "evil".getBytes(StandardCharsets.UTF_8));

    MockMultipartFile zipFile = new MockMultipartFile(
        "uploadedFileZipSlip", "attack.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
