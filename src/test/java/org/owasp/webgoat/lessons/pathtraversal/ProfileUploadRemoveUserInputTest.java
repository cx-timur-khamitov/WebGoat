/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.File;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class ProfileUploadRemoveUserInputTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void solve() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileRemoveUserInput", "../picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-remove-user-input")
                .file(profilePicture)
                .param("fullNameFix", "John Doe"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUploadRemoveUserInput")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  void normalUpdate() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileRemoveUserInput", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-remove-user-input")
                .file(profilePicture)
                .param("fullNameFix", "John Doe"))
        .andExpect(status().is(200))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.containsString("test\\" + File.separator + "picture.jpg")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that a filename with a relative path traversal sequence (../name) is blocked
   * by the containment check added to ProfileUploadBase.execute().
   * The fix uses Path.normalize().startsWith() to reject any resolved path that escapes
   * the user's upload directory.
   */
  @Test
  void pathTraversalViaOriginalFilenameIsBlocked() throws Exception {
    // Attacker crafts a multipart upload whose original filename contains "../"
    var maliciousFile =
        new MockMultipartFile(
            "uploadedFileRemoveUserInput",
            "../malicious.jpg",
            "text/plain",
            "malicious content".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-remove-user-input")
                .file(maliciousFile))
        .andExpect(status().is(200))
        // The containment check must reject the traversal attempt — lesson must NOT be completed
        // and the response must indicate failure, not a successful upload
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that a deeply nested path traversal (../../.. sequence) in the original filename
   * is also rejected by the containment check.
   */
  @Test
  void deepPathTraversalViaOriginalFilenameIsBlocked() throws Exception {
    var maliciousFile =
        new MockMultipartFile(
            "uploadedFileRemoveUserInput",
            "../../etc/passwd",
            "text/plain",
            "root:x:0:0".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-remove-user-input")
                .file(maliciousFile))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
