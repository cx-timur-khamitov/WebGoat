/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
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

/**
 * Tests for the Zip Slip path traversal fix in ProfileZipSlip.
 *
 * <p>The fix ensures ZIP entry names that contain path traversal sequences (e.g. "../") are
 * rejected before being extracted to disk, preventing writes outside the designated temp directory.
 */
@WithWebGoatUser
class ProfileZipSlipTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  // ---------------------------------------------------------------------------
  // Helper: build an in-memory ZIP file with a single entry
  // ---------------------------------------------------------------------------
  private byte[] buildZip(String entryName, byte[] content) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      ZipEntry entry = new ZipEntry(entryName);
      zos.putNextEntry(entry);
      zos.write(content);
      zos.closeEntry();
    }
    return baos.toByteArray();
  }

  // ---------------------------------------------------------------------------
  // Attack scenario: ZIP entry with "../" path traversal should be rejected
  // ---------------------------------------------------------------------------

  /**
   * A crafted ZIP whose entry name starts with "../" attempts to escape the temporary extraction
   * directory. After the fix, the endpoint must return a failure response rather than extracting
   * the file to the parent directory.
   */
  @Test
  void zipSlipWithParentTraversalShouldBeBlocked() throws Exception {
    // Entry name uses "../" to try to write one level above tmpZipDirectory
    byte[] zipBytes = buildZip("../evil.jpg", "malicious content".getBytes());
    MockMultipartFile zipFile =
        new MockMultipartFile("uploadedFileZipSlip", "upload.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        // The lesson must NOT be marked completed when the attack is blocked
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * A deeply nested path traversal entry (multiple "../" segments) must also be rejected.
   */
  @Test
  void zipSlipWithDeepTraversalShouldBeBlocked() throws Exception {
    byte[] zipBytes = buildZip("../../etc/passwd", "root:x:0:0".getBytes());
    MockMultipartFile zipFile =
        new MockMultipartFile("uploadedFileZipSlip", "upload.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  // ---------------------------------------------------------------------------
  // Normal scenario: a well-formed ZIP with a safe entry name should be accepted
  // ---------------------------------------------------------------------------

  /**
   * A legitimate ZIP upload with a safe filename (no traversal) must be processed without error
   * and must NOT trigger the traversal-detected feedback path.
   */
  @Test
  void normalZipUploadWithSafeEntryNameShouldSucceed() throws Exception {
    byte[] zipBytes = buildZip("profile.jpg", "fake image bytes".getBytes());
    MockMultipartFile zipFile =
        new MockMultipartFile("uploadedFileZipSlip", "upload.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        // A normal upload (non-traversal) should not report the traversal-detected message
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.not(CoreMatchers.containsString("zip-slip-detected"))));
  }

  // ---------------------------------------------------------------------------
  // Non-zip upload: endpoint rejects files that are not .zip
  // ---------------------------------------------------------------------------

  /**
   * Uploading a file with a non-.zip extension must be rejected with the appropriate feedback.
   */
  @Test
  void nonZipFileShouldBeRejected() throws Exception {
    MockMultipartFile notAZip =
        new MockMultipartFile(
            "uploadedFileZipSlip", "image.jpg", "image/jpeg", "fake jpg".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(notAZip))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.containsString("path-traversal-zip-slip.no-zip")));
  }
}
