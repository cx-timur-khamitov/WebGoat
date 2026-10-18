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
class ProfileUploadTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  /**
   * Path traversal via fullName is now blocked by the containment check in
   * ProfileUploadBase.execute(). A "../" prefix should be rejected and not escape the upload
   * directory.
   */
  @Test
  void pathTraversalViaSingleDotDotIsBlocked() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFile", "../picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "../John Doe"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUpload")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** A deep traversal attempt (multiple "../") must also be blocked. */
  @Test
  @WithWebGoatUser
  void pathTraversalViaMultipleDotDotsIsBlocked() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFile", "../picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "../../" + "test"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUpload")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** An absolute path in fullName that resolves outside the upload directory must be blocked. */
  @Test
  @WithWebGoatUser
  void pathTraversalViaAbsolutePathIsBlocked() throws Exception {
    var profilePicture =
        new MockMultipartFile("uploadedFile", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "/etc/passwd"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** A legitimate filename that does not traverse the directory should succeed. */
  @Test
  void normalUpdate() throws Exception {
    var profilePicture =
        new MockMultipartFile("uploadedFile", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", "John Doe"))
        .andExpect(status().is(200))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.containsStringIgnoringCase(
                    "PathTraversal" + File.separator + "test" + File.separator + "John Doe")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** An empty file should return an appropriate error. */
  @Test
  void emptyFileIsRejected() throws Exception {
    var emptyFile =
        new MockMultipartFile("uploadedFile", "picture.jpg", "text/plain", new byte[0]);

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(emptyFile)
                .param("fullName", "John Doe"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** An empty fullName should return an appropriate error. */
  @Test
  void emptyFullNameIsRejected() throws Exception {
    var profilePicture =
        new MockMultipartFile("uploadedFile", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload")
                .file(profilePicture)
                .param("fullName", ""))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
