package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.request.LoginRequest;
import com.revature.passwordmanager.dto.response.AuthResponse;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private AuthenticationManager authenticationManager;

  @Mock
  private JwtTokenProvider tokenProvider;

  @InjectMocks
  private AuthenticationService authenticationService;

  private LoginRequest loginRequest;
  private User user;

  @BeforeEach
  void setUp() {
    loginRequest = new LoginRequest();
    loginRequest.setUsername("testuser");
    loginRequest.setMasterPassword("password123");

    user = new User();
    user.setUsername("testuser");
    user.setEmail("test@example.com");
  }

  @Test
  void testLogin_Success() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenReturn(mock(Authentication.class));
    when(tokenProvider.generateAccessToken(any(Authentication.class))).thenReturn("accessToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("refreshToken");

    AuthResponse response = authenticationService.login(loginRequest);

    assertNotNull(response);
    assertEquals("accessToken", response.getAccessToken());
    assertEquals("refreshToken", response.getRefreshToken());
  }

  @Test
  void testLogin_UserNotFound() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.empty());
    when(userRepository.findByEmail(loginRequest.getUsername())).thenReturn(Optional.empty());

    assertThrows(AuthenticationException.class, () -> authenticationService.login(loginRequest));
  }
}
