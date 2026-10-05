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

@WithWebGoatUser
class ProfileZipSlipTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  /** Helper: build an in-memory ZIP whose single entry has the given name. */
  private byte[] buildZipWithEntry(String entryName, byte[] content) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      ZipEntry entry = new ZipEntry(entryName);
      zos.putNextEntry(entry);
      zos.write(content);
      zos.closeEntry();
    }
    return baos.toByteArray();
  }

  // -----------------------------------------------------------------------
  // Non-malicious uploads
  // -----------------------------------------------------------------------

  @Test
  void uploadNonZipFileShouldFail() throws Exception {
    // A non-ZIP file must be rejected with a specific feedback message.
    MockMultipartFile notAZip =
        new MockMultipartFile(
            "uploadedFileZipSlip", "image.jpg", "image/jpeg", "fake image data".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(notAZip))
        .andExpect(status().is(200))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.containsString("no-zip")));
  }

  @Test
  void uploadLegitimateZipShouldSucceedWithoutError() throws Exception {
    // A well-formed ZIP with a safe entry name must be accepted and processed.
    byte[] zipBytes = buildZipWithEntry("profile.jpg", "fake image content".getBytes());
    MockMultipartFile zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "upload.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200));
    // No assertion on lessonCompleted because the test environment may or may not
    // flip the profile image; we just verify no server error occurs.
  }

  // -----------------------------------------------------------------------
  // Zip Slip attack vectors — all must be blocked after the fix
  // -----------------------------------------------------------------------

  @Test
  void zipSlipWithRelativePathTraversalShouldNotEscapeDirectory() throws Exception {
    // Entry name uses "../" to escape the extraction directory.
    // The fix must detect this and return an error, NOT write the file outside the temp dir.
    byte[] zipBytes =
        buildZipWithEntry("../../evil.sh", "malicious content".getBytes());
    MockMultipartFile zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "attack.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        // The fix throws an IOException that is caught and returned as a failed AttackResult.
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void zipSlipWithAbsolutePathEntryShouldNotEscapeDirectory() throws Exception {
    // Some Zip Slip payloads use an absolute path as the entry name (e.g. /etc/cron.d/evil).
    // After normalize() + startsWith() the path will not start with tmpZipDirectory.
    byte[] zipBytes =
        buildZipWithEntry("/etc/cron.d/evil", "* * * * * root id".getBytes());
    MockMultipartFile zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "absolute.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void zipSlipWithMixedSeparatorsShouldNotEscapeDirectory() throws Exception {
    // Mixed separators that normalize to a traversal sequence.
    byte[] zipBytes =
        buildZipWithEntry("subdir/../../escape.txt", "payload".getBytes());
    MockMultipartFile zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "mixed.zip", "application/zip", zipBytes);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
