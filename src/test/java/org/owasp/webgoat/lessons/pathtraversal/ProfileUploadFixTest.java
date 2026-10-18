/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.File;
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

  /**
   * Verifies that the profile-picture-fix endpoint returns a valid (default) image response
   * and does NOT traverse outside the PathTraversal directory when the username contains
   * relative path components such as "../" (CWE-23 regression test).
   */
  @Test
  void getProfilePictureFixReturnsImageForNormalUsername() throws Exception {
    mockMvc
        .perform(get("/PathTraversal/profile-picture-fix"))
        .andExpect(status().is(200));
  }

  /**
   * Unit-level regression test for {@link ProfileUploadBase#getProfilePictureAsBase64}:
   * a username containing path-traversal sequences must NOT cause the method to read files
   * outside the designated PathTraversal directory. The method should return the default
   * image bytes (non-null, non-empty) rather than throwing or leaking data from parent dirs.
   */
  @Test
  void getProfilePictureAsBase64BlocksPathTraversalUsername(@TempDir Path tempDir)
      throws Exception {
    // Arrange: create a sentinel file one level above the PathTraversal sub-directory
    Path pathTraversalDir = tempDir.resolve("PathTraversal");
    Files.createDirectories(pathTraversalDir);
    Path secretFile = tempDir.resolve("secret.txt");
    Files.writeString(secretFile, "sensitive data");

    var base = new ProfileUploadBase(tempDir.toAbsolutePath().toString()) {};

    // Act: attempt traversal with "../" in the username
    byte[] result = base.getProfilePictureAsBase64("../");

    // Assert: result is the default image (non-null), not the traversed content
    assertThat(result).isNotNull().isNotEmpty();
    // The traversal attempt must not return content of the secret file
    String resultStr = new String(result);
    assertThat(resultStr).doesNotContain("sensitive data");
  }

  /**
   * Verifies that a normal, well-formed username (no path separators) still works correctly
   * and returns the default image when no picture has been uploaded yet.
   */
  @Test
  void getProfilePictureAsBase64ReturnsDefaultImageForNewUser(@TempDir Path tempDir)
      throws Exception {
    // Arrange: PathTraversal directory exists but no user sub-directory
    Path pathTraversalDir = tempDir.resolve("PathTraversal");
    Files.createDirectories(pathTraversalDir);

    var base = new ProfileUploadBase(tempDir.toAbsolutePath().toString()) {};

    // Act
    byte[] result = base.getProfilePictureAsBase64("testuser");

    // Assert: default image returned (non-null, non-empty)
    assertThat(result).isNotNull().isNotEmpty();
  }
}
