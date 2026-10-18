/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Holds solution constants for WebGoat challenge lessons. The admin password is loaded from the
 * {@code WEBGOAT_ADMIN_PASSWORD} environment variable (or the {@code webgoat.challenge.admin.password}
 * application property), so it is no longer hardcoded in the source.
 */
@Configuration
public class SolutionConstants {

  private final String password;

  public SolutionConstants(
      @Value("${webgoat.challenge.admin.password}") String password) {
    this.password = password;
  }

  public String getPassword() {
    return password;
  }
}
