/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import lombok.Getter;

@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes

  private static final int SALT_BYTES = 16;

  private final String username;
  private final boolean admin;
  private String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      this.userHash = genUserHash(user.getUsername(), user.getPassword());
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  protected String genUserHash(String username, String password) throws Exception {
    // Generate a cryptographically random per-user salt (CWE-760 fix: unpredictable salt)
    SecureRandom secureRandom = new SecureRandom();
    byte[] saltBytes = new byte[SALT_BYTES];
    secureRandom.nextBytes(saltBytes);

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(saltBytes);
    md.update(username.getBytes(StandardCharsets.UTF_8));
    byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));

    // Encode salt + hash together so the hash can be verified later: base64(salt || hash)
    byte[] saltedHash = new byte[saltBytes.length + hash.length];
    System.arraycopy(saltBytes, 0, saltedHash, 0, saltBytes.length);
    System.arraycopy(hash, 0, saltedHash, saltBytes.length, hash.length);
    return Base64.getEncoder().encodeToString(saltedHash);
  }

  /**
   * Verifies a password against a stored hash produced by {@link #genUserHash(String, String)}.
   * The stored hash encodes the random salt as the first {@value #SALT_BYTES} bytes followed by
   * the SHA-256 digest.
   */
  public boolean verifyUserHash(String username, String password, String storedHash)
      throws Exception {
    byte[] decoded = Base64.getDecoder().decode(storedHash);
    if (decoded.length < SALT_BYTES) {
      return false;
    }
    byte[] saltBytes = Arrays.copyOfRange(decoded, 0, SALT_BYTES);
    byte[] expectedHash = Arrays.copyOfRange(decoded, SALT_BYTES, decoded.length);

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(saltBytes);
    md.update(username.getBytes(StandardCharsets.UTF_8));
    byte[] actualHash = md.digest(password.getBytes(StandardCharsets.UTF_8));

    // Constant-time comparison to prevent timing attacks
    return MessageDigest.isEqual(expectedHash, actualHash);
  }
}
