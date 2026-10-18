/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
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

  /** Creates a zip file in memory with a single entry using the given entry name. */
  private byte[] createZipWithEntry(String entryName, byte[] entryContent) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      ZipEntry entry = new ZipEntry(entryName);
      zos.putNextEntry(entry);
      zos.write(entryContent);
      zos.closeEntry();
    }
    return baos.toByteArray();
  }

  @Test
  void uploadNonZipFileShouldFail() throws Exception {
    var nonZipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "profile.txt", "text/plain", "not a zip".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(nonZipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void zipWithNormalEntryNameShouldBeExtracted() throws Exception {
    // A zip with a normal entry name (no traversal) should be processed without error
    byte[] zipContent = createZipWithEntry("profile.jpg", "fake image content".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "profile.zip", "application/zip", zipContent);

    mockMvc
        .perform(MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200));
  }

  @Test
  void zipSlipWithAbsolutePathEntryShouldBeBlocked() throws Exception {
    // Zip Slip attack: entry with absolute path that would escape the temp directory
    byte[] zipContent = createZipWithEntry("/etc/passwd", "malicious content".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "malicious.zip", "application/zip", zipContent);

    mockMvc
        .perform(MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void zipSlipWithRelativeTraversalEntryShouldBeBlocked() throws Exception {
    // Zip Slip attack: entry name uses ../ to escape the temp directory
    byte[] zipContent =
        createZipWithEntry("../../malicious.txt", "malicious content".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "traversal.zip", "application/zip", zipContent);

    mockMvc
        .perform(MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void zipSlipWithDeepRelativeTraversalShouldBeBlocked() throws Exception {
    // Zip Slip attack: deep ../ traversal to reach system directories
    byte[] zipContent =
        createZipWithEntry("../../../../../tmp/malicious.sh", "#!/bin/bash\necho pwned".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "deep-traversal.zip", "application/zip", zipContent);

    mockMvc
        .perform(MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void zipSlipWithSubdirectoryEntryContainingTraversalShouldBeBlocked() throws Exception {
    // Zip Slip attack: entry nested in a subdirectory, then traversing out
    byte[] zipContent =
        createZipWithEntry("subdir/../../malicious.txt", "malicious content".getBytes());
    var zipFile =
        new MockMultipartFile(
            "uploadedFileZipSlip", "subdir-traversal.zip", "application/zip", zipContent);

    mockMvc
        .perform(MockMvcRequestBuilders.multipart("/PathTraversal/zip-slip").file(zipFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
