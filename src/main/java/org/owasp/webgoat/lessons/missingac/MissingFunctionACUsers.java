/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/** Created by jason on 1/5/17. */
@Controller
@Slf4j
public class MissingFunctionACUsers {

  private final MissingAccessControlUserRepository userRepository;
  // Salts loaded from external configuration; override via environment variables
  private final String passwordSaltSimple;
  private final String passwordSaltAdmin;

  public MissingFunctionACUsers(
      MissingAccessControlUserRepository userRepository,
      @Value("${webgoat.password.salt.simple}") String passwordSaltSimple,
      @Value("${webgoat.password.salt.admin}") String passwordSaltAdmin) {
    this.userRepository = userRepository;
    this.passwordSaltSimple = passwordSaltSimple;
    this.passwordSaltAdmin = passwordSaltAdmin;
  }

  @GetMapping(path = {"access-control/users"})
  public ModelAndView listUsers() {

    ModelAndView model = new ModelAndView();
    model.setViewName("list_users");
    List<User> allUsers = userRepository.findAllUsers();
    model.addObject("numUsers", allUsers.size());
    // add display user objects in place of direct users
    List<DisplayUser> displayUsers = new ArrayList<>();
    for (User user : allUsers) {
      displayUsers.add(new DisplayUser(user, passwordSaltSimple));
    }
    model.addObject("allUsers", displayUsers);

    return model;
  }

  @GetMapping(
      path = {"access-control/users"},
      consumes = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersService() {
    return ResponseEntity.ok(
        userRepository.findAllUsers().stream()
            .map(user -> new DisplayUser(user, passwordSaltSimple))
            .collect(Collectors.toList()));
  }

  @GetMapping(
      path = {"access-control/users-admin-fix"},
      consumes = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersFixed(@CurrentUsername String username) {
    var currentUser = userRepository.findByUsername(username);
    if (currentUser != null && currentUser.isAdmin()) {
      return ResponseEntity.ok(
          userRepository.findAllUsers().stream()
              .map(user -> new DisplayUser(user, passwordSaltAdmin))
              .collect(Collectors.toList()));
    }
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
  }

  @PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public User addUser(@RequestBody User newUser) {
    try {
      userRepository.save(newUser);
      return newUser;
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return null;
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }
}
