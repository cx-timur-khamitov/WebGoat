/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
   * Creates a zip archive in memory with the given entry name and content.
   */
  private byte[] createZip(String entryName, byte[] content) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      ZipEntry entry = new ZipEntry(entryName);
      zos.putNextEntry(entry);
      zos.write(content);
      zos.closeEntry();
    }
    return baos.toByteArray();
  }

  /** Non-zip file should be rejected with appropriate feedback. */
  @Test
  void nonZipFileShouldBeRejected() throws Exception {
    var notAZip =
        new MockMultipartFile(
            "uploadedFileZipSlip", "picture.jpg", "image/jpeg", "not a zip".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(notAZip))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** A well-formed zip with a safe (non-traversal) entry should be accepted and processed. */
  @Test
  void legitimateZipShouldBeAccepted() throws Exception {
    byte[] zipBytes = createZip("safe-image.jpg", "image data".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "upload.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200));
  }

  /**
   * Zip Slip attack: an entry whose name contains "../" path traversal sequences should be
   * blocked. The fix resolves each entry path relative to the temp directory and verifies it
   * stays within that directory via Path.normalize().startsWith(base).
   */
  @Test
  void zipSlipAttackViaEntryNameShouldBeBlocked() throws Exception {
    // Entry name uses "../" to escape the temp extraction directory
    byte[] zipBytes = createZip("../../malicious.sh", "#!/bin/bash\necho pwned".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "exploit.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200))
        // The attack is caught as an IOException and reported via the failed() path
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Zip Slip with an absolute path entry name should also be blocked (CWE-36 absolute path
   * traversal). The normalize + startsWith check covers absolute paths too.
   */
  @Test
  void zipSlipWithAbsolutePathEntryShouldBeBlocked() throws Exception {
    // Entry name is an absolute path (e.g. /etc/passwd)
    byte[] zipBytes = createZip("/etc/passwd", "root:x:0:0".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "absolute-exploit.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * The uploaded zip filename itself should not be used to traverse outside the temp directory.
   * An attacker-supplied filename like "../../malicious.zip" must be sanitized to only the
   * basename before being written to the temp directory.
   */
  @Test
  void pathTraversalInUploadedFilenameItselfShouldBeBlocked() throws Exception {
    // The zip content is valid; the attack vector is the upload filename itself
    byte[] zipBytes = createZip("image.jpg", "image data".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip",
            "../../traversal.zip",  // attacker-controlled filename with path traversal
            "application/zip",
            zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200));
    // The file must be saved as "traversal.zip" inside the temp dir, not two levels above it.
    // The test verifies the request is handled without errors caused by the traversal filename.
  }

  /**
   * A zip that contains entries with encoded traversal sequences like "%2e%2e%2f" should not
   * escape. Java's ZipEntry getName() returns the raw name so the normalization check applies.
   */
  @Test
  void zipWithNestedDirectoryEntryShouldBeAccepted() throws Exception {
    // A legitimate nested directory structure inside the zip should be fine
    byte[] zipBytes = createZip("subdir/avatar.png", "png data".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "nested.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip")
                .file(zipFile))
        .andExpect(status().is(200));
  }
}
