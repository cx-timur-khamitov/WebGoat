/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  /** Password salt for simple (non-admin) user hashes. Loaded from configuration. */
  @Value("${webgoat.missingac.salt.simple}")
  private String passwordSaltSimple;

  /** Password salt for admin user hashes. Loaded from configuration. */
  @Value("${webgoat.missingac.salt.admin}")
  private String passwordSaltAdmin;

  public String getPasswordSaltSimple() {
    return passwordSaltSimple;
  }

  public String getPasswordSaltAdmin() {
    return passwordSaltAdmin;
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
