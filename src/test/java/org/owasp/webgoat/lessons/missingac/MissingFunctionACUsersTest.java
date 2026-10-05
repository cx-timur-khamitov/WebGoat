/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import java.util.List;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.MockMvc;
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

  // ── usersFixed endpoint tests (CWE-472 Parameter Tampering fix) ─────────────

  /**
   * A non-admin authenticated user must receive 403 FORBIDDEN from the admin-only
   * fixed endpoint. The default test user ("test") has no record in the lesson DB
   * so {@code currentUser} will be null and access is denied.
   */
  @Test
  void usersFixed_nonAdminUser_returnsForbidden() throws Exception {
    // Default @WithWebGoatUser has username "test" which does not exist as admin in the DB
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users-admin-fix")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());
  }

  /**
   * Verifies that the server-side validation added for CWE-472 rejects a null/blank
   * username before it ever reaches the database layer.
   * Uses standalone MockMvc so no real auth context injects a principal — simulating
   * a scenario where the security context provides no username.
   */
  @Test
  void usersFixed_nullUsername_returnsForbiddenWithoutQueryingDatabase() throws Exception {
    MissingAccessControlUserRepository repoMock =
        mock(MissingAccessControlUserRepository.class);
    MissingFunctionACUsers controller = new MissingFunctionACUsers(repoMock);

    MockMvc standalone = standaloneSetup(controller).build();

    // Perform request; @CurrentUsername resolves to null in a bare standalone context
    standalone
        .perform(
            MockMvcRequestBuilders.get("/access-control/users-admin-fix")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());

    // The repository must never be called when the username fails validation
    verify(repoMock, never()).findByUsername(null);
    verify(repoMock, never()).findAllUsers();
  }

  /**
   * Verifies that a user identified as admin in the lesson database receives 200 OK
   * and the full user list when accessing the admin-fixed endpoint.
   * Uses standalone MockMvc with a mock repository to inject an admin principal.
   */
  @Test
  void usersFixed_adminUser_returnsUserList() throws Exception {
    MissingAccessControlUserRepository repoMock =
        mock(MissingAccessControlUserRepository.class);
    // "Jerry" is the admin user in the lesson DB seed data
    User adminUser = new User("Jerry", "doesnotreallymatter", true);
    User regularUser = new User("Tom", "qwertyqwerty1234", false);
    when(repoMock.findByUsername("Jerry")).thenReturn(adminUser);
    when(repoMock.findAllUsers()).thenReturn(List.of(adminUser, regularUser));

    MissingFunctionACUsers controller = new MissingFunctionACUsers(repoMock);
    MockMvc standalone = standaloneSetup(controller).build();

    // Pass a non-null, non-blank username via query param to simulate @CurrentUsername
    // resolving to "Jerry" through a custom argument resolver is not straightforward
    // in pure standalone — instead we verify the controller logic by injecting a mock
    // where findByUsername("Jerry") returns an admin user.
    // The controller is invoked directly to cover the positive code path.
    var result = controller.usersFixed("Jerry");
    assert result.getStatusCode().value() == 200;
    assert result.getBody() != null;
    assert result.getBody().size() == 2;

    verify(repoMock).findByUsername("Jerry");
    verify(repoMock).findAllUsers();
  }

  /**
   * Verifies that a non-admin DB user (username found but admin=false) receives 403 FORBIDDEN.
   */
  @Test
  void usersFixed_nonAdminDbUser_returnsForbidden() throws Exception {
    MissingAccessControlUserRepository repoMock =
        mock(MissingAccessControlUserRepository.class);
    User regularUser = new User("Tom", "qwertyqwerty1234", false);
    when(repoMock.findByUsername("Tom")).thenReturn(regularUser);

    MissingFunctionACUsers controller = new MissingFunctionACUsers(repoMock);

    var result = controller.usersFixed("Tom");
    assert result.getStatusCode().value() == 403;

    // findAllUsers must NOT be called — no data leak to unauthorised users
    verify(repoMock, never()).findAllUsers();
  }

  /**
   * Verifies that an empty string username is rejected before touching the database
   * (covers the blank-string branch of StringUtils.hasText).
   */
  @Test
  void usersFixed_emptyUsername_returnsForbiddenWithoutQueryingDatabase() throws Exception {
    MissingAccessControlUserRepository repoMock =
        mock(MissingAccessControlUserRepository.class);
    MissingFunctionACUsers controller = new MissingFunctionACUsers(repoMock);

    var result = controller.usersFixed("  ");
    assert result.getStatusCode().value() == 403;

    verify(repoMock, never()).findByUsername(org.mockito.ArgumentMatchers.any());
    verify(repoMock, never()).findAllUsers();
  }
}
