/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.Getter;

@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes

  private final String username;
  private final boolean admin;
  private String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      // Generate a cryptographically random per-instance salt (16 bytes = 128 bits)
      SecureRandom secureRandom = new SecureRandom();
      byte[] randomSaltBytes = new byte[16];
      secureRandom.nextBytes(randomSaltBytes);
      String randomSalt = Base64.getEncoder().encodeToString(randomSaltBytes);
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), randomSalt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    // Use the provided salt (should be a cryptographically random, per-invocation value)
    String salted = password + passwordSalt + username;
    byte[] hash = md.digest(salted.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }
}
