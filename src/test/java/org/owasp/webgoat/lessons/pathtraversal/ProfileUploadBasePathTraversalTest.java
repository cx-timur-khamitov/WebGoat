/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the path-traversal fix in {@link ProfileUploadBase#cleanupAndCreateDirectoryForUser}.
 *
 * <p>The fix uses {@code Path.normalize().toAbsolutePath()} combined with a {@code startsWith}
 * containment check to ensure the resolved user directory never escapes the base
 * {@code /PathTraversal} directory, regardless of what the username value contains.
 */
class ProfileUploadBasePathTraversalTest {

  @TempDir Path tempDir;

  private ProfileUploadBase profileUploadBase;

  // Concrete subclass to make the abstract-ish base instantiable without a full Spring context.
  private static class TestableProfileUploadBase extends ProfileUploadBase {
    TestableProfileUploadBase(String webGoatHomeDirectory) {
      super(webGoatHomeDirectory);
    }
  }

  @BeforeEach
  void setUp() {
    profileUploadBase = new TestableProfileUploadBase(tempDir.toString());
  }

  // -----------------------------------------------------------------------
  // Positive test: a safe (non-traversing) username creates the correct dir
  // -----------------------------------------------------------------------

  @Test
  void safeUsernameCreatesDirectoryInsideBase() throws IOException {
    File result = profileUploadBase.cleanupAndCreateDirectoryForUser("alice");

    Path baseDir = tempDir.resolve("PathTraversal").normalize().toAbsolutePath();
    assertThat(result.toPath().toAbsolutePath()).startsWith(baseDir);
    assertThat(result).exists().isDirectory();
    assertThat(result.getName()).isEqualTo("alice");
  }

  // -----------------------------------------------------------------------
  // Negative tests: path-traversal payloads in the username must be rejected
  // -----------------------------------------------------------------------

  /**
   * A username containing {@code ../} sequences should cause an IOException because after
   * normalization the resolved path would escape the expected base directory.
   */
  @ParameterizedTest(name = "username with traversal payload [{0}] is rejected")
  @ValueSource(
      strings = {
        "../secret",
        "../../etc/passwd",
        "../../../root",
        "..",
        "alice/../../../etc",
        "alice/../../outside",
      })
  void usernameWithPathTraversalIsRejected(String maliciousUsername) {
    assertThatThrownBy(() -> profileUploadBase.cleanupAndCreateDirectoryForUser(maliciousUsername))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Path traversal");
  }

  /** Absolute path as username must not escape the base directory. */
  @Test
  void absolutePathUsernameIsRejected() {
    // An absolute path like "/etc/passwd" — after resolve this replaces the base entirely
    assertThatThrownBy(() -> profileUploadBase.cleanupAndCreateDirectoryForUser("/etc/passwd"))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Path traversal");
  }

  /** Verify that the created directory is strictly contained within the PathTraversal base. */
  @Test
  void createdDirectoryIsStrictlyWithinBase() throws IOException {
    File result = profileUploadBase.cleanupAndCreateDirectoryForUser("bob");

    Path baseDir = tempDir.resolve("PathTraversal").normalize().toAbsolutePath();
    Path resultPath = result.toPath().normalize().toAbsolutePath();

    // Must start with base (containment check mirrors the production fix)
    assertThat(resultPath).startsWith(baseDir);
    // Must not be the base itself — must be a child
    assertThat(resultPath).isNotEqualTo(baseDir);
  }

  /**
   * Calling the method twice for the same username should clean up the old directory and recreate
   * it, verifying idempotency of the cleanup+create logic is unaffected by the fix.
   */
  @Test
  void directoryIsRecreatedOnSecondCall() throws IOException {
    File first = profileUploadBase.cleanupAndCreateDirectoryForUser("carol");
    new File(first, "marker.txt").createNewFile();
    assertThat(new File(first, "marker.txt")).exists();

    File second = profileUploadBase.cleanupAndCreateDirectoryForUser("carol");
    // Should be the same path
    assertThat(second.getAbsolutePath()).isEqualTo(first.getAbsolutePath());
    // Old contents should be gone
    assertThat(new File(second, "marker.txt")).doesNotExist();
    assertThat(second).exists().isDirectory();
  }
}
