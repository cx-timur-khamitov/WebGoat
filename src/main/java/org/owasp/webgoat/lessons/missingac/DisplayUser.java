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
  private static final int HASH_LENGTH_BITS = 256;
  private static final int SALT_LENGTH_BYTES = 16;

  private final String username;
  private final boolean admin;
  private String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      // Generate a cryptographically random salt per user hash (replaces the predictable static salt)
      SecureRandom random = new SecureRandom();
      byte[] salt = new byte[SALT_LENGTH_BYTES];
      random.nextBytes(salt);
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), salt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  /**
   * Generates a PBKDF2WithHmacSHA256 hash with a random salt, encoded as
   * {@code <base64salt>$<base64hash>} so that the salt can be recovered for
   * verification without a separate storage field.
   *
   * @param username    the user's username (used as additional input)
   * @param password    the user's password to hash
   * @param salt        a cryptographically random salt (at least 16 bytes)
   * @return            the encoded string containing both salt and hash
   * @throws Exception  if the PBKDF2WithHmacSHA256 algorithm is unavailable
   */
  protected String genUserHash(String username, String password, byte[] salt) throws Exception {
    // PBKDF2WithHmacSHA256 with 310,000 iterations (NIST SP 800-132 guidance)
    // incorporates username so hashes are unique per user even with the same password
    char[] input = (password + username).toCharArray();
    KeySpec spec = new PBEKeySpec(input, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BITS);
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    byte[] hash = factory.generateSecret(spec).getEncoded();
    // Embed the salt in the output so verification can recompute without separate salt storage
    return Base64.getEncoder().encodeToString(salt)
        + "$"
        + Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Verifies a candidate hash (submitted by a user) against a freshly generated hash that uses
   * the same embedded salt.  Extracts the random salt from {@code storedHash}, recomputes the
   * hash for the given credentials, and performs a constant-time comparison to prevent
   * timing-based attacks.
   *
   * @param username      the user's username
   * @param password      the user's password
   * @param storedHash    the stored hash in {@code <base64salt>$<base64hash>} format
   * @return              {@code true} if the credentials match the stored hash
   */
  public static boolean verifyUserHash(String username, String password, String storedHash)
      throws Exception {
    String[] parts = storedHash.split("\\$", 2);
    if (parts.length != 2) {
      return false;
    }
    byte[] salt = Base64.getDecoder().decode(parts[0]);
    char[] input = (password + username).toCharArray();
    KeySpec spec = new PBEKeySpec(input, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BITS);
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    byte[] hash = factory.generateSecret(spec).getEncoded();
    String recomputed = Base64.getEncoder().encodeToString(salt)
        + "$"
        + Base64.getEncoder().encodeToString(hash);
    // Constant-time comparison to prevent timing oracle attacks
    return java.security.MessageDigest.isEqual(
        recomputed.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        storedHash.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
}
