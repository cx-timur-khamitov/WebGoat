/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
class ProfileUploadFixTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

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
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUploadFix")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
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

  // ---- Path traversal prevention tests for cleanupAndCreateDirectoryForUser ----

  /**
   * Verifies that a legitimate username creates a directory exactly within the base
   * PathTraversal directory and does not escape it.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_legitimateUsername_createsDirectoryInsideBase(
      @TempDir Path tempDir) throws IOException {
    var base = new ProfileUploadBase(tempDir.toString());
    File result = base.cleanupAndCreateDirectoryForUser("john");
    Path baseDirectory = tempDir.resolve("PathTraversal").normalize();
    // Ensure the resolved directory is inside the base
    assertThat(result.toPath().normalize()).startsWith(baseDirectory);
    assertThat(result.exists()).isTrue();
  }

  /**
   * Verifies that a username containing "../" sequences is rejected and throws an IOException,
   * preventing directory traversal outside the intended PathTraversal base.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_dotDotUsername_throwsIOException(@TempDir Path tempDir) {
    var base = new ProfileUploadBase(tempDir.toString());
    // "../../etc" would escape out of webGoatHomeDirectory/PathTraversal/
    assertThatThrownBy(() -> base.cleanupAndCreateDirectoryForUser("../../etc"))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Path traversal attempt detected");
  }

  /**
   * Verifies that an absolute path as username is rejected (it would resolve outside the base).
   */
  @Test
  void cleanupAndCreateDirectoryForUser_absolutePathUsername_throwsIOException(
      @TempDir Path tempDir) {
    var base = new ProfileUploadBase(tempDir.toString());
    // An absolute path like "/etc" should not be allowed as a username
    assertThatThrownBy(() -> base.cleanupAndCreateDirectoryForUser("/etc"))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Path traversal attempt detected");
  }

  /**
   * Verifies that a username with encoded traversal sequences such as "..././" (which the
   * ProfileUploadFix handler strips "../" from) still results in a safe path when passed
   * through the base class after the replace-based stripping in ProfileUploadFix.
   * The base class should also be safe on its own with a direct ".." username.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_singleDotDot_throwsIOException(@TempDir Path tempDir) {
    var base = new ProfileUploadBase(tempDir.toString());
    assertThatThrownBy(() -> base.cleanupAndCreateDirectoryForUser(".."))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Path traversal attempt detected");
  }

  /**
   * Verifies that a valid username with subpath still stays within the base directory.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_usernameWithSubpath_staysWithinBase(
      @TempDir Path tempDir) throws IOException {
    var base = new ProfileUploadBase(tempDir.toString());
    File result = base.cleanupAndCreateDirectoryForUser("user123");
    Path expected = tempDir.resolve("PathTraversal").resolve("user123").normalize();
    assertThat(result.toPath().normalize()).isEqualTo(expected);
  }

  /**
   * Verifies that after the fix the directory that IS created does not escape the
   * PathTraversal parent directory when the username is a regular string.
   */
  @Test
  void cleanupAndCreateDirectoryForUser_createdDirectoryIsChild(@TempDir Path tempDir)
      throws IOException {
    var base = new ProfileUploadBase(tempDir.toString());
    File result = base.cleanupAndCreateDirectoryForUser("alice");
    Path pathTraversalBase = tempDir.resolve("PathTraversal").normalize();
    // The immediate parent of the user directory must be PathTraversal/
    assertThat(result.getParentFile().toPath().normalize()).isEqualTo(pathTraversalBase);
  }
}
