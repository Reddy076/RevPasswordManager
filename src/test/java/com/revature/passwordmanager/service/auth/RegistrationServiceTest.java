package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.request.RegistrationRequest;
import com.revature.passwordmanager.dto.response.UserResponse;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.security.MasterPasswordValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegistrationServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private MasterPasswordValidator passwordValidator;

  @InjectMocks
  private RegistrationService registrationService;

  private RegistrationRequest request;

  @BeforeEach
  void setUp() {
    request = new RegistrationRequest();
    request.setUsername("testuser");
    request.setEmail("test@example.com");
    request.setMasterPassword("StrongPassword123!");
  }

  @Test
  void testRegisterUser_Success() {
    when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
    when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
    when(passwordValidator.isValid(request.getMasterPassword())).thenReturn(true);
    when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
    when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
      User user = invocation.getArgument(0);
      user.setId(1L);
      return user;
    });

    UserResponse response = registrationService.registerUser(request);

    assertNotNull(response);
    assertEquals(request.getUsername(), response.getUsername());
    assertEquals(request.getEmail(), response.getEmail());
    verify(userRepository).save(any(User.class));
  }

  @Test
  void testRegisterUser_DuplicateUsername() {
    when(userRepository.existsByUsername(request.getUsername())).thenReturn(true);

    assertThrows(AuthenticationException.class, () -> registrationService.registerUser(request));
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  void testRegisterUser_DuplicateEmail() {
    when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

    assertThrows(AuthenticationException.class, () -> registrationService.registerUser(request));
    verify(userRepository, never()).save(any(User.class));
  }
}
