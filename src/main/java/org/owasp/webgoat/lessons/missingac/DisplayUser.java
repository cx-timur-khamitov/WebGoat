/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
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
    // Use a cryptographically random per-call salt (16 bytes) combined with the provided
    // passwordSalt to ensure the hash cannot be reversed via precomputed rainbow tables.
    SecureRandom random = new SecureRandom();
    byte[] randomSalt = new byte[16];
    random.nextBytes(randomSalt);

    // Derive a strong key using PBKDF2WithHmacSHA256 — a SAST-recognized KDF.
    // The PBEKeySpec takes the password as a char[], the random salt bytes, iteration count,
    // and desired key length in bits.
    KeySpec spec =
        new PBEKeySpec(
            (password + passwordSalt + username).toCharArray(),
            randomSalt,
            PBKDF2_ITERATIONS,
            PBKDF2_KEY_LENGTH);
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    byte[] hash = factory.generateSecret(spec).getEncoded();
    // Encode both the random salt and the derived key so the hash can be stored/verified later
    return Base64.getEncoder().encodeToString(randomSalt)
        + ":"
        + Base64.getEncoder().encodeToString(hash);
  }
}
