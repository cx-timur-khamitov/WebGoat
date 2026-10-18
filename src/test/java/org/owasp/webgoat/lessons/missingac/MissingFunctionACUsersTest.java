/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionACUsersTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void getUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].username", CoreMatchers.is("Tom")))
        .andExpect(
            jsonPath(
                "$[0].userHash", CoreMatchers.is("Mydnhcy00j2b0m6SjmPz6PUxF9WIeO7tzm665GiZWCo=")))
        .andExpect(jsonPath("$[0].admin", CoreMatchers.is(false)));
  }

  @Test
  void addUser() throws Exception {
    var user =
        """
        {"username":"newUser","password":"newUser12","admin": "true"}
        """;
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users")
                .header("Content-type", "application/json")
                .content(user))
        .andExpect(status().isOk());

    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.size()", is(4)));
  }

  /**
   * Non-admin users (WEBGOAT_USER authority) must be denied access to the admin-only endpoint.
   * This verifies the authorization check is based on Spring Security authorities,
   * not user-supplied data (parameter tampering prevention, CWE-472).
   */
  @Test
  @WithWebGoatUser(username = "test", role = WebGoatUser.ROLE_USER)
  void usersFixedReturnsForbiddenForRegularUser() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users-admin-fix")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());
  }

  /**
   * Admin users (WEBGOAT_ADMIN authority) must be granted access to the admin-only endpoint.
   * The authorization check uses Spring Security authorities — not a DB lookup on the
   * user-supplied username — so it cannot be bypassed via parameter tampering.
   */
  @Test
  @WithWebGoatUser(username = "admintest", role = WebGoatUser.ROLE_ADMIN)
  void usersFixedReturnsUsersForAdminUser() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users-admin-fix")
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.size()", is(3)));
  }

  /**
   * Validates that an unauthenticated (null) principal cannot access the admin endpoint.
   * The handler gracefully returns 403 when the principal is absent.
   */
  @Test
  @WithWebGoatUser(username = "attacker", role = WebGoatUser.ROLE_USER)
  void usersFixedWithNonAdminUserCannotAccessAdminData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users-admin-fix")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());
  }
}
