/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.lang.reflect.Field;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Verifies that the password salt values for the Missing Function Access Control lesson are loaded
 * from external configuration (application properties / environment variables) and are NOT
 * hardcoded as static constants in MissingFunctionAC. Fixes CWE-259 (Use of Hard-coded Password).
 */
class MissingFunctionACPasswordSaltConfigTest extends LessonTest {

  @Value("${webgoat.password.salt.simple}")
  private String injectedSaltSimple;

  @Value("${webgoat.password.salt.admin}")
  private String injectedSaltAdmin;

  @Autowired private MissingFunctionACYourHash yourHashEndpoint;
  @Autowired private MissingFunctionACYourHashAdmin yourHashAdminEndpoint;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  /**
   * Confirms that MissingFunctionAC no longer exposes hardcoded salt constants as public static
   * fields — the class must not have fields named PASSWORD_SALT_SIMPLE or PASSWORD_SALT_ADMIN.
   */
  @Test
  void saltConstantsAreNotHardcodedInMissingFunctionACClass() {
    Field[] fields = MissingFunctionAC.class.getDeclaredFields();
    for (Field field : fields) {
      assertThat(field.getName())
          .as("MissingFunctionAC must not expose a hardcoded salt constant named '%s'", field.getName())
          .doesNotContain("PASSWORD_SALT");
    }
  }

  /**
   * Confirms that the salt values are injected from application properties and are not empty.
   * The actual values are supplied by application-webgoat-test.properties in the test environment.
   */
  @Test
  void saltValuesAreInjectedFromConfiguration() {
    assertThat(injectedSaltSimple)
        .as("webgoat.password.salt.simple must be non-null and non-empty when loaded from config")
        .isNotNull()
        .isNotEmpty();
    assertThat(injectedSaltAdmin)
        .as("webgoat.password.salt.admin must be non-null and non-empty when loaded from config")
        .isNotNull()
        .isNotEmpty();
  }

  /**
   * Exercises the /access-control/user-hash sink: a hash computed with the configured simple salt
   * must be accepted, proving that the @Value injection wires up correctly end-to-end.
   */
  @Test
  void userHashEndpointAcceptsHashComputedWithConfiguredSimpleSalt() throws Exception {
    // Compute the expected hash using the salt loaded from config (same path as production code)
    User testUser = new User("Jerry", "doesnotreallymatter", false);
    String expectedHash = new DisplayUser(testUser, injectedSaltSimple).getUserHash();

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash")
                .param("userHash", expectedHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  /**
   * Exercises the /access-control/user-hash sink: a hash computed with an arbitrary string that
   * is NOT the configured salt must be rejected.
   */
  @Test
  void userHashEndpointRejectsHashComputedWithWrongSalt() throws Exception {
    String wrongSalt = "completelywrongsalt";
    User testUser = new User("Jerry", "doesnotreallymatter", false);
    String wrongHash = new DisplayUser(testUser, wrongSalt).getUserHash();

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash").param("userHash", wrongHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Exercises the /access-control/user-hash-fix sink: a hash computed with the configured admin
   * salt must be accepted.
   */
  @Test
  void userHashAdminEndpointAcceptsHashComputedWithConfiguredAdminSalt() throws Exception {
    User testUser = new User("Jerry", "doesnotreallymatter", true);
    String expectedHash = new DisplayUser(testUser, injectedSaltAdmin).getUserHash();

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix")
                .param("userHash", expectedHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  /**
   * Exercises the /access-control/user-hash-fix sink: a hash computed with the wrong salt must be
   * rejected.
   */
  @Test
  void userHashAdminEndpointRejectsHashComputedWithWrongSalt() throws Exception {
    String wrongSalt = "completelywrongsalt";
    User testUser = new User("Jerry", "doesnotreallymatter", true);
    String wrongHash = new DisplayUser(testUser, wrongSalt).getUserHash();

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix")
                .param("userHash", wrongHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
