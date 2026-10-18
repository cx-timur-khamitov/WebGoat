/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import lombok.Getter;

@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes

  private static final int PBKDF2_ITERATIONS = 310_000;
  private static final int PBKDF2_KEY_LENGTH = 256;

  private final String username;
  private final boolean admin;
  private String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), passwordSalt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    // Use PBKDF2WithHmacSHA256 — a secure key derivation function — instead of raw SHA-256.
    // Raw SHA-256 is a fast hash and does not provide adequate protection for passwords
    // (CWE-522). PBKDF2 applies a high iteration count to make brute-force attacks expensive.
    byte[] salt = (passwordSalt + username).getBytes(StandardCharsets.UTF_8);
    PBEKeySpec spec =
        new PBEKeySpec(
            password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      byte[] hash = skf.generateSecret(spec).getEncoded();
      return Base64.getEncoder().encodeToString(hash);
    } finally {
      spec.clearPassword();
    }
  }
}
