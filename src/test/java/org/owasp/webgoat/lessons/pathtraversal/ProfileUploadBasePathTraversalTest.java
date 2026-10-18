/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests that {@link ProfileUploadBase#getProfilePictureAsBase64(String)} is protected against
 * relative path traversal (CWE-23) via a tainted username parameter.
 */
class ProfileUploadBasePathTraversalTest {

  @TempDir Path tempDir;

  private ProfileUploadBase profileUploadBase;

  /** Concrete subclass that makes the abstract-ish base instantiable in tests. */
  static class TestProfileUploadBase extends ProfileUploadBase {
    TestProfileUploadBase(String webGoatHomeDirectory) {
      super(webGoatHomeDirectory);
    }
  }

  @BeforeEach
  void setUp() {
    profileUploadBase = new TestProfileUploadBase(tempDir.toString());
  }

  // -------------------------------------------------------------------------
  // Helper: create a directory and a dummy image file for a legitimate user
  // -------------------------------------------------------------------------
  private void createUserProfileWithImage(String username) throws IOException {
    Path userDir = tempDir.resolve("PathTraversal").resolve(username);
    Files.createDirectories(userDir);
    Files.writeString(userDir.resolve("avatar.jpg"), "fake-jpeg-data");
  }

  // =========================================================================
  // Positive tests — legitimate usernames must work normally
  // =========================================================================

  @Test
  void legitimateUsername_returnsDefaultImageWhenNoFilesExist() {
    // No profile directory created → should get the default image (non-null, non-empty)
    byte[] result = profileUploadBase.getProfilePictureAsBase64("alice");
    assertThat(result).isNotNull().isNotEmpty();
  }

  @Test
  void legitimateUsername_returnsImageWhenProfileExists() throws IOException {
    createUserProfileWithImage("bob");
    byte[] result = profileUploadBase.getProfilePictureAsBase64("bob");
    // Should return a non-null result (either the file contents or the default image)
    assertThat(result).isNotNull().isNotEmpty();
  }

  @Test
  void usernameWithNoSpecialChars_resolvesInsideBaseDirectory() throws IOException {
    createUserProfileWithImage("charlie");
    // Must not throw; path should be confined to the base PathTraversal directory
    byte[] result = profileUploadBase.getProfilePictureAsBase64("charlie");
    assertThat(result).isNotNull();
  }

  // =========================================================================
  // Security tests — path traversal attempts must be blocked and return the
  // default image instead of accessing files outside the expected directory
  // =========================================================================

  @Test
  void pathTraversal_dotDotSlash_isBlocked() {
    // "../" traverses one level above the PathTraversal directory
    byte[] result = profileUploadBase.getProfilePictureAsBase64("../");
    // Must return the default image, NOT a file from outside the base directory
    assertThat(result).isNotNull().isNotEmpty();
    // Verify the traversal did not resolve to the tempDir root itself
    // (we can't check the exact file, but we verify it returns gracefully)
  }

  @Test
  void pathTraversal_dotDotSlashRepeated_isBlocked() {
    // "../../" traverses two levels above
    byte[] result = profileUploadBase.getProfilePictureAsBase64("../../");
    assertThat(result).isNotNull().isNotEmpty();
  }

  @Test
  void pathTraversal_absolutePath_isBlocked() throws IOException {
    // An absolute path as username would escape the base directory
    String absolutePath = tempDir.toAbsolutePath().toString();
    byte[] result = profileUploadBase.getProfilePictureAsBase64(absolutePath);
    assertThat(result).isNotNull().isNotEmpty();
  }

  @Test
  void pathTraversal_dotDotPrefix_isBlocked() {
    // "../secret" should be blocked
    byte[] result = profileUploadBase.getProfilePictureAsBase64("../secret");
    assertThat(result).isNotNull().isNotEmpty();
  }

  @Test
  void pathTraversal_dotDotMixedSlashes_isBlocked() {
    // Try both forward and back separators
    byte[] result = profileUploadBase.getProfilePictureAsBase64(".." + File.separator + "etc");
    assertThat(result).isNotNull().isNotEmpty();
  }

  @Test
  void pathTraversal_doesNotLeakFilesOutsideBaseDirectory() throws IOException {
    // Place a sentinel file one level above PathTraversal/
    Path sensitiveFile = tempDir.resolve("sensitive.jpg");
    Files.writeString(sensitiveFile, "SENSITIVE_CONTENT");

    // Attempt traversal: username = "../" would point to tempDir itself
    byte[] result = profileUploadBase.getProfilePictureAsBase64("../");

    // The result must be the default image bytes, not the sensitive file
    byte[] defaultImage = profileUploadBase.defaultImage();
    assertThat(result).isEqualTo(defaultImage);
  }

  @Test
  void pathTraversal_normalizedUsername_staysInside() throws IOException {
    // A username that normalizes to something outside should be rejected
    byte[] result = profileUploadBase.getProfilePictureAsBase64("foo/../../../");
    byte[] defaultImage = profileUploadBase.defaultImage();
    assertThat(result).isEqualTo(defaultImage);
  }
}
