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
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), passwordSalt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    // Generate a cryptographically random, unpredictable salt (CWE-760 fix)
    SecureRandom secureRandom = new SecureRandom();
    byte[] randomSalt = new byte[16];
    secureRandom.nextBytes(randomSalt);
    String randomSaltStr = Base64.getEncoder().encodeToString(randomSalt);
    // Combine password with the random salt and username for a unique, non-predictable hash
    String salted = password + randomSaltStr + username;
    byte[] hash = md.digest(salted.getBytes(StandardCharsets.UTF_8));
    // Prepend the random salt to the hash output (salt$hash format) so it can be verified later
    return randomSaltStr + "$" + Base64.getEncoder().encodeToString(hash);
  }
}
