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
class ProfileUploadFixTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  /** Original solve test: "..././" bypass used to be possible; now blocked by Path.normalize(). */
  @Test
  void solve() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileFix", "../picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-fix")
                .file(profilePicture)
                .param("fullNameFix", "..././John Doe"))
        .andExpect(status().is(200))
        // With the path-containment fix the traversal is blocked; the lesson is NOT completed.
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void normalUpdate() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileFix", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-fix")
                .file(profilePicture)
                .param("fullNameFix", "John Doe"))
        .andExpect(status().is(200))
        .andExpect(
            jsonPath(
                "$.feedback", CoreMatchers.containsString("test\\" + File.separator + "John Doe")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Regression test: classic "../" traversal in fullName must be blocked by the
   * Path.normalize() + startsWith() containment check (CWE-23 fix).
   */
  @Test
  void pathTraversalWithDotDotSlashIsBlocked() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileFix", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-fix")
                .file(profilePicture)
                .param("fullNameFix", "../evil.jpg"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Regression test: absolute path injection in fullName must be blocked.
   * Path.resolve() of an absolute path replaces the base; normalize() + startsWith()
   * catches this and rejects the request.
   */
  @Test
  void absolutePathInjectionIsBlocked() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileFix", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-fix")
                .file(profilePicture)
                .param("fullNameFix", "/etc/passwd"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Regression test: the old replace("../","") defence was bypassable via "..././".
   * After the Path.normalize() fix this pattern must also be blocked.
   */
  @Test
  void dotDotSlashObfuscatedTraversalIsBlocked() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileFix", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-fix")
                .file(profilePicture)
                // "..././" reduces to "../" after the old replace() but is now caught
                // by normalize() + startsWith() before the file is touched.
                .param("fullNameFix", "..././evil"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
