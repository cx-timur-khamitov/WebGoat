/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.mailbox;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.mockito.ArgumentMatchers.anyList;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

class MailboxControllerTest extends LessonTest {

  @MockitoBean private MailboxRepository mailbox;

  // Spring Boot 4's auto-configured mapper is Jackson 3; this test drives the Jackson 2
  // ObjectMapper directly to build the request body, so instantiate it here. Register modules so
  // java.time types (Email#getTimestamp) serialize.
  private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

  @JsonIgnoreProperties("time")
  public static class EmailMixIn {}

  private Authentication user(String username) {
    return UsernamePasswordAuthenticationToken.authenticated(username, "password", List.of());
  }

  @BeforeEach
  public void setupMixIn() {
    objectMapper.addMixIn(Email.class, EmailMixIn.class);
  }

  @Test
  public void sendingMailShouldStoreIt() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    this.mockMvc
        .perform(
            post("/mail")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(email)))
        .andExpect(status().isCreated());
  }

  @Test
  public void userShouldBeAbleToReadOwnEmail() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mockMvc
        .perform(get("/mail").principal(user("test1234")))
        .andExpect(status().isOk())
        .andExpect(view().name("mailbox"))
        .andExpect(content().string(containsString("Click this mail")))
        .andExpect(
            content()
                .string(
                    containsString(
                        DateTimeFormatter.ofPattern("h:mm a").format(email.getTimestamp()))));
  }

  @Test
  public void countShouldReturnNumberOfUnreadEmailsForCurrentUser() throws Exception {
    Mockito.when(mailbox.countByRecipientAndReadFalse("test1234")).thenReturn(1);

    this.mockMvc
        .perform(get("/mail/count").principal(user("test1234")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.count", is(1)));
  }

  @Test
  public void openingMailboxMarksEmailsAsRead() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .read(false)
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mockMvc.perform(get("/mail").principal(user("test1234"))).andExpect(status().isOk());

    // Opening the mailbox flips the unread mail to read and persists it.
    assertThat(email.isRead()).isTrue();
    Mockito.verify(mailbox).saveAll(anyList());
  }

  @Test
  public void differentUserShouldNotBeAbleToReadOwnEmail() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mockMvc
        .perform(get("/mail").principal(user("test1233")))
        .andExpect(status().isOk())
        .andExpect(view().name("mailbox"))
        .andExpect(content().string(not(containsString("Click this mail"))));
  }

  // ── Validation tests verifying the CWE-472 parameter-tampering fix ──────────

  @Test
  public void sendEmailWithMissingRecipientShouldBeRejected() throws Exception {
    // An attacker omitting the recipient field must be rejected (400 Bad Request)
    // before the tainted value reaches mailboxRepository.save().
    String body =
        "{\"sender\":\"attacker@webgoat.org\",\"title\":\"Title\","
            + "\"contents\":\"Payload\",\"recipient\":\"\"}";
    this.mockMvc
        .perform(post("/mail").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sendEmailWithMissingSenderShouldBeRejected() throws Exception {
    // An attacker omitting the sender field must be rejected (400 Bad Request)
    // so they cannot impersonate an arbitrary sender identity.
    String body =
        "{\"sender\":\"\",\"title\":\"Title\","
            + "\"contents\":\"Payload\",\"recipient\":\"victim@webgoat.org\"}";
    this.mockMvc
        .perform(post("/mail").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sendEmailWithMissingContentsShouldBeRejected() throws Exception {
    // Empty contents must be rejected to prevent blank-payload tampering.
    String body =
        "{\"sender\":\"sender@webgoat.org\",\"title\":\"Title\","
            + "\"contents\":\"\",\"recipient\":\"victim@webgoat.org\"}";
    this.mockMvc
        .perform(post("/mail").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sendEmailWithMissingTitleShouldBeRejected() throws Exception {
    // Empty title must be rejected.
    String body =
        "{\"sender\":\"sender@webgoat.org\",\"title\":\"\","
            + "\"contents\":\"Some content\",\"recipient\":\"victim@webgoat.org\"}";
    this.mockMvc
        .perform(post("/mail").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sendEmailWithNullRecipientShouldBeRejected() throws Exception {
    // A null recipient must be rejected to prevent unvalidated CRUD writes.
    String body =
        "{\"sender\":\"sender@webgoat.org\",\"title\":\"Title\","
            + "\"contents\":\"Some content\"}";
    this.mockMvc
        .perform(post("/mail").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sendEmailWithRecipientExceedingMaxLengthShouldBeRejected() throws Exception {
    // A recipient longer than 255 characters must be rejected.
    String longRecipient = "a".repeat(256) + "@webgoat.org";
    String body =
        "{\"sender\":\"sender@webgoat.org\",\"title\":\"Title\","
            + "\"contents\":\"Some content\",\"recipient\":\""
            + longRecipient
            + "\"}";
    this.mockMvc
        .perform(post("/mail").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sendEmailWithAllValidFieldsIsAccepted() throws Exception {
    // A fully-populated, valid email must still be accepted (regression guard).
    String body =
        "{\"sender\":\"sender@webgoat.org\",\"title\":\"Hello\","
            + "\"contents\":\"Valid content\",\"recipient\":\"user@webgoat.org\"}";
    this.mockMvc
        .perform(post("/mail").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isCreated());
  }
}
