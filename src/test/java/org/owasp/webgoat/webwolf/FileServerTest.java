/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

class FileServerTest {

  private static final String USERNAME = "tweety";
  private static final Authentication AUTHENTICATION =
      new UsernamePasswordAuthenticationToken(USERNAME, "n/a");

  @TempDir private Path fileServerLocation;

  private MockMvc mockMvc;

  @BeforeEach
  void setupFileServer() throws IOException {
    var fileServer = new FileServer();
    ReflectionTestUtils.setField(fileServer, "fileLocation", fileServerLocation.toString());
    ReflectionTestUtils.setField(fileServer, "server", "127.0.0.1");
    ReflectionTestUtils.setField(fileServer, "contextPath", "/WebWolf");
    ReflectionTestUtils.setField(fileServer, "port", 9090);

    // the view names ('files') are resolved by Thymeleaf at runtime, without a prefix/suffix the
    // standalone setup would forward '/files' onto itself and fail with a circular view path
    mockMvc =
        MockMvcBuilders.standaloneSetup(fileServer)
            .setViewResolvers(new InternalResourceViewResolver("/webwolf/templates/", ".html"))
            .build();
  }

  @Test
  @DisplayName("The configured file server location is exposed as plain text")
  void shouldReturnFileServerLocation() throws Exception {
    mockMvc
        .perform(get("/file-server-location"))
        .andExpect(status().isOk())
        .andExpect(result -> Assertions.assertThat(result.getResponse().getContentAsString())
            .isEqualTo(fileServerLocation.toString()));
  }

  @Test
  void shouldIgnoreUploadWithoutContentAndStoreTheNextUpload() throws Exception {
    FileUtils.cleanDirectory(fileServerLocation.toFile());
    mockMvc
        .perform(multipart("/fileupload").file(emptyUpload()).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=Nothing+to+upload"));

    Assertions.assertThat(uploadedFiles()).isEmpty();

    mockMvc
        .perform(multipart("/fileupload").file(testFile()).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=File+uploaded+successful"));

    Assertions.assertThat(userDirectory().resolve("test.txt")).content().isEqualTo("test");
  }

  @Test
  @DisplayName("An uploaded file is listed on the files page")
  void shouldListUploadedFile() throws Exception {
    mockMvc.perform(multipart("/fileupload").file(testFile()).principal(AUTHENTICATION));

    mockMvc
        .perform(get("/files").principal(AUTHENTICATION))
        .andExpect(status().isOk())
        .andExpect(view().name("files"))
        .andExpect(model().attribute("webwolf_url", "http://127.0.0.1:9090/WebWolf"))
        .andExpect(
            result -> {
              var files = (List<?>) result.getModelAndView().getModel().get("files");
              Assertions.assertThat(files).hasSize(1);
              Assertions.assertThat(files.get(0).toString())
                  .contains("test.txt")
                  .contains("files/%s/test.txt".formatted(USERNAME));
            });
  }

  @Test
  @DisplayName("The message of the upload we are redirected from is passed on to the files page")
  void shouldShowUploadMessageFromRedirect() throws Exception {
    mockMvc
        .perform(
            get("/files")
                .param("uploadSuccess", FileServer.UPLOAD_TOO_LARGE)
                .principal(AUTHENTICATION))
        .andExpect(status().isOk())
        .andExpect(model().attribute("uploadSuccess", FileServer.UPLOAD_TOO_LARGE))
        .andExpect(model().attribute("uploadFailed", true));

    mockMvc
        .perform(
            get("/files")
                .param("uploadSuccess", FileServer.UPLOAD_SUCCESSFUL)
                .principal(AUTHENTICATION))
        .andExpect(model().attribute("uploadFailed", false));

    // no message means no alert on the files page
    mockMvc
        .perform(get("/files").principal(AUTHENTICATION))
        .andExpect(model().attributeDoesNotExist("uploadSuccess", "uploadFailed"));
  }

  // -------------------------------------------------------------------------
  // Path traversal security tests (CWE-23 / Relative_Path_Traversal)
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("Upload with a relative path traversal filename is rejected")
  void shouldRejectRelativePathTraversalFilename() throws Exception {
    // Attacker crafts a filename that tries to escape the per-user upload directory
    var traversalFile =
        new MockMultipartFile(
            "file",
            "../../etc/passwd",
            "text/plain",
            "malicious content".getBytes(StandardCharsets.UTF_8));

    mockMvc
        .perform(multipart("/fileupload").file(traversalFile).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection());

    // The sensitive target must NOT have been written outside the upload directory
    var passwdFile = fileServerLocation.getParent().resolve("etc/passwd");
    Assertions.assertThat(passwdFile).doesNotExist();
    // Nothing should have landed in the user directory either (rejected)
    Assertions.assertThat(uploadedFiles()).isEmpty();
  }

  @Test
  @DisplayName("Upload with a Windows-style path traversal filename is rejected")
  void shouldRejectWindowsStylePathTraversalFilename() throws Exception {
    var traversalFile =
        new MockMultipartFile(
            "file",
            "..\\..\\windows\\system32\\config\\sam",
            "application/octet-stream",
            "malicious".getBytes(StandardCharsets.UTF_8));

    mockMvc
        .perform(multipart("/fileupload").file(traversalFile).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection());

    // Only the base filename (if any) may end up in the user directory
    var samFile =
        fileServerLocation
            .getParent()
            .resolve("windows")
            .resolve("system32")
            .resolve("config")
            .resolve("sam");
    Assertions.assertThat(samFile).doesNotExist();
  }

  @Test
  @DisplayName("Upload with a path-only filename (no basename) is treated as nothing-to-upload")
  void shouldRejectFilenameWithNoBasenameAfterStripping() throws Exception {
    // A filename like "../../" has no basename after stripping directory components
    var traversalOnlyFile =
        new MockMultipartFile(
            "file",
            "../",
            "text/plain",
            "malicious".getBytes(StandardCharsets.UTF_8));

    mockMvc
        .perform(multipart("/fileupload").file(traversalOnlyFile).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=Nothing+to+upload"));

    Assertions.assertThat(uploadedFiles()).isEmpty();
  }

  @Test
  @DisplayName("A normal filename with directory prefix is stored under its basename only")
  void shouldStoreFileUsingOnlyItsBasename() throws Exception {
    // "subdir/report.txt" — directory part must be stripped, only "report.txt" is stored
    var nestedFile =
        new MockMultipartFile(
            "file",
            "subdir/report.txt",
            "text/plain",
            "content".getBytes(StandardCharsets.UTF_8));

    mockMvc
        .perform(multipart("/fileupload").file(nestedFile).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=File+uploaded+successful"));

    // File must land directly in the user directory, not in a sub-directory
    Assertions.assertThat(userDirectory().resolve("report.txt")).exists();
    Assertions.assertThat(userDirectory().resolve("subdir")).doesNotExist();
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private Path userDirectory() {
    return fileServerLocation.resolve(USERNAME);
  }

  private List<Path> uploadedFiles() throws Exception {
    try (var files = Files.walk(fileServerLocation)) {
      return files.filter(Files::isRegularFile).toList();
    }
  }

  private MockMultipartFile emptyUpload() {
    return new MockMultipartFile("file", "", "application/octet-stream", new byte[0]);
  }

  private MockMultipartFile testFile() {
    return new MockMultipartFile(
        "file", "test.txt", "text/plain", "test".getBytes(StandardCharsets.UTF_8));
  }
}
