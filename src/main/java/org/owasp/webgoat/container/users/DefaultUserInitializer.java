/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Seeds default accounts on first startup so that the platform is immediately usable
 * without manual database intervention.
 *
 * <p>If the users already exist, their credentials are left untouched (for normal users)
 * or re-ensured (for admins), making this bean idempotent across restarts.
 */
@Component
@Slf4j
public class DefaultUserInitializer implements ApplicationRunner {

  private static final String ADMIN_USERNAME = "webgoat-admin";
  private static final String DEFAULT_USER_USERNAME = "webgoat-user";

  private final UserRepository userRepository;
  private final UserService userService;

  /**
   * The default password for seeded demo accounts, loaded from the external configuration
   * property {@code webgoat.default.password} (overridable via the {@code WEBGOAT_DEFAULT_PASSWORD}
   * environment variable). The password is never stored as a literal in source code so that
   * operators can rotate it without rebuilding the application.
   */
  private final String defaultPassword;

  @Autowired
  public DefaultUserInitializer(
      UserRepository userRepository,
      UserService userService,
      @Value("${webgoat.default.password}") String defaultPassword) {
    this.userRepository = userRepository;
    this.userService = userService;
    this.defaultPassword = defaultPassword;
  }

  @Override
  public void run(ApplicationArguments args) {
    // 1. Seed the default admin
    if (userRepository.existsByUsername(ADMIN_USERNAME)) {
      // Always ensure the admin has the correct role AND the known demo password so that
      // the credentials remain predictable after every restart regardless of mid-session resets.
      userRepository.save(
          new WebGoatUser(ADMIN_USERNAME, defaultPassword, WebGoatUser.ROLE_ADMIN));
      log.info(
          "Ensured '{}' account is WEBGOAT_ADMIN with the default demo password.",
          ADMIN_USERNAME);
    } else {
      userRepository.save(new WebGoatUser(ADMIN_USERNAME, defaultPassword, WebGoatUser.ROLE_ADMIN));
      log.info(
          "Created default admin account '{}' with role {}.",
          ADMIN_USERNAME,
          WebGoatUser.ROLE_ADMIN);
    }

    // 2. Seed the default regular user
    if (!userRepository.existsByUsername(DEFAULT_USER_USERNAME)) {
      // Use UserService here because it properly provisions lessons and progress trackers
      // for a normal user, which is required for them to actually play the game.
      userService.addUser(DEFAULT_USER_USERNAME, defaultPassword);
      log.info("Created default regular user account '{}' and provisioned lessons.", DEFAULT_USER_USERNAME);
    } else {
      log.info("Default regular user account '{}' already exists. Skipping initialization.", DEFAULT_USER_USERNAME);
    }
  }
}
