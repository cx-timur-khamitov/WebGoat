/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.server.ResponseStatusException;

@Controller
@RequiredArgsConstructor
@Slf4j
public class RegistrationController {

  private final UserValidator userValidator;
  private final UserService userService;

  @GetMapping("/registration")
  public String showForm(UserForm userForm) {
    return "registration";
  }

  @PostMapping("/register.mvc")
  public String registration(
      @ModelAttribute("userForm") @Valid UserForm userForm,
      BindingResult bindingResult,
      HttpServletRequest request,
      HttpServletResponse response)
      throws ServletException {
    userValidator.validate(userForm, bindingResult);

    if (bindingResult.hasErrors()) {
      return "registration";
    }

    // Logout current user if any
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null) {
      new SecurityContextLogoutHandler().logout(request, response, auth);
    }

    userService.addUser(userForm.getUsername(), userForm.getPassword());
    request.login(userForm.getUsername(), userForm.getPassword());

    return "redirect:/attack";
  }

  /** Allowed OAuth username pattern: same constraint enforced by {@link UserForm#username}. */
  private static final java.util.regex.Pattern VALID_USERNAME =
      java.util.regex.Pattern.compile("[a-z0-9-]{6,45}");

  @GetMapping("/login-oauth.mvc")
  public String registrationOAUTH(Authentication authentication, HttpServletRequest request)
      throws ServletException {
    log.info("register oauth user in database");
    String name = authentication.getName();
    // Validate the OAuth-supplied username against the same allowlist used by the
    // standard registration form (UserForm). Reject names that do not conform to
    // prevent parameter-tampering attacks via a manipulated OAuth principal.
    if (name == null || !VALID_USERNAME.matcher(name).matches()) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST, "Invalid username supplied by OAuth provider");
    }
    userService.addUser(name, UUID.randomUUID().toString());
    return "redirect:/welcome.mvc";
  }
}
