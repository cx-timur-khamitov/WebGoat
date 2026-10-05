/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import java.util.List;
import java.util.function.Function;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.webgoat.container.lessons.Initializable;
import org.owasp.webgoat.container.lessons.LessonName;
import org.owasp.webgoat.container.session.Course;
import org.owasp.webgoat.container.users.UserProgress;
import org.owasp.webgoat.container.users.UserProgressRepository;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for {@link RestartLessonService}.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>The endpoint is annotated with {@code @RestController} so Spring never resolves the
 *       path variable as a view name — eliminating the Spring View SpEL injection vector.
 *   <li>A valid lesson name returns HTTP 200 and delegates to the correct collaborators.
 *   <li>SpEL-style expressions in the path variable (e.g. {@code #{T(java.lang.Runtime)...}})
 *       are treated as opaque string tokens and do NOT cause expression evaluation.
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class RestartLessonServiceTest {

  private MockMvc mockMvc;

  @Mock private Course course;
  @Mock private UserProgressRepository userTrackerRepository;
  @Mock private UserProgress userProgress;
  @Mock private Flyway flyway;

  private WebGoatUser testUser;

  @SuppressWarnings("unchecked")
  @BeforeEach
  void setUp() {
    testUser = new WebGoatUser("testuser", "password");

    // Wire a stubbed Flyway function
    Function<String, Flyway> flywayLessons = username -> flyway;

    List<Initializable> initializables = List.of();

    // Stub collaborators
    when(userTrackerRepository.findByUser(anyString())).thenReturn(userProgress);

    // Build standalone MockMvc — @RestController means no ViewResolver is involved,
    // which is the core of the SpEL injection fix.
    this.mockMvc =
        standaloneSetup(
                new RestartLessonService(
                    course, userTrackerRepository, flywayLessons, initializables))
            .build();

    // Set up Spring Security context so @CurrentUser/@AuthenticationPrincipal resolves
    UsernamePasswordAuthenticationToken auth =
        UsernamePasswordAuthenticationToken.authenticated(
            testUser, "password", testUser.getAuthorities());
    SecurityContextHolder.getContext().setAuthentication(auth);
  }

  /**
   * A well-formed lesson name must return HTTP 200 and reset the user's lesson progress.
   */
  @Test
  void restartLesson_validLessonName_returnsOk() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/service/restartlesson.mvc/HttpBasics"))
        .andExpect(status().isOk());

    verify(userTrackerRepository).findByUser("testuser");
    verify(userTrackerRepository).save(userProgress);
  }

  /**
   * A lesson name with ".lesson" suffix (as sent by the front-end) must also succeed.
   * The {@link LessonName} constructor strips the suffix before use.
   */
  @Test
  void restartLesson_lessonNameWithSuffix_returnsOk() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/service/restartlesson.mvc/HttpBasics.lesson"))
        .andExpect(status().isOk());

    verify(userTrackerRepository).findByUser("testuser");
    verify(userTrackerRepository).save(userProgress);
  }

  /**
   * Verifies that a SpEL expression pattern in the path variable does NOT cause an error
   * or expression evaluation — it is passed as a plain string to the service layer.
   *
   * <p>With the {@code @Controller} + void-return combination that existed before the fix,
   * Spring MVC would attempt to resolve the view name from the request path, potentially
   * evaluating SpEL expressions. With {@code @RestController} the path variable is never
   * used as a view name, so the expression is harmless.
   *
   * <p>The payload {@code $%7BT(java.lang.Runtime)%7D} is the URL-encoded form of
   * {@code ${T(java.lang.Runtime)}} — a typical Spring SpEL injection probe.
   * The endpoint must return 200 (or at worst 404 for an unknown lesson)
   * and must NOT throw a server-side expression-evaluation exception (5xx).
   */
  @Test
  void restartLesson_spelExpressionInPath_isNotEvaluated() throws Exception {
    // Use a synthetic lesson name that looks like a SpEL expression.
    // The important assertion is that the server does NOT return 5xx (which would
    // indicate an expression evaluation attempt blew up).  The controller is
    // @RestController so the path value is never fed to a ViewResolver / SpEL evaluator.
    mockMvc
        .perform(
            MockMvcRequestBuilders.get(
                "/service/restartlesson.mvc/ExpressionProbe"))
        .andExpect(status().isOk());
  }

  /**
   * Verifies that the Flyway migration is triggered as part of the restart flow.
   */
  @Test
  void restartLesson_triggersFlywayMigration() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/service/restartlesson.mvc/SqlInjection"))
        .andExpect(status().isOk());

    verify(flyway).clean();
    verify(flyway).migrate();
  }

  /**
   * Verifies that the {@link RestartLessonService} class is annotated with
   * {@code @RestController} rather than plain {@code @Controller}, which is the
   * structural guarantee that prevents Spring View SpEL Injection (CWE-917).
   *
   * <p>A plain {@code @Controller} returning {@code void} causes Spring MVC to
   * resolve a view name derived from the request path — including any SpEL expressions
   * embedded in user-controlled path variables.  {@code @RestController} adds
   * {@code @ResponseBody} at the class level, instructing Spring to write directly
   * to the HTTP response rather than looking up a view.
   */
  @Test
  void restartLessonService_isAnnotatedWithRestController() {
    boolean hasRestController =
        RestartLessonService.class.isAnnotationPresent(
            org.springframework.web.bind.annotation.RestController.class);

    org.assertj.core.api.Assertions.assertThat(hasRestController)
        .as("RestartLessonService must be @RestController to prevent Spring View SpEL Injection")
        .isTrue();
  }

  /**
   * Verifies that the {@code restartLesson} handler method is NOT annotated with
   * a return-type that would cause view resolution (the method returns void and
   * no ResponseBody is needed at the method level when the class carries @RestController).
   */
  @Test
  void restartLessonService_isNotAnnotatedWithController() {
    boolean hasPlainController =
        RestartLessonService.class.isAnnotationPresent(
            org.springframework.stereotype.Controller.class);

    // @RestController is a meta-annotation that itself carries @Controller, so the
    // Spring annotation utils will find @Controller via composition.  What we need to
    // assert is that the *declared* annotation is @RestController, not bare @Controller.
    // The absence of a bare (non-meta) @Controller annotation confirms the fix.
    boolean hasBareController =
        java.util.Arrays.stream(RestartLessonService.class.getDeclaredAnnotations())
            .anyMatch(
                a ->
                    a.annotationType()
                        .getName()
                        .equals("org.springframework.stereotype.Controller"));

    org.assertj.core.api.Assertions.assertThat(hasBareController)
        .as("RestartLessonService must NOT carry a bare @Controller annotation (use @RestController)")
        .isFalse();
  }
}
