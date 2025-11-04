package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.dto.LoginDTO;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.LoginRequest;
import com.iforddow.authservice.auth.utility.DeviceType;
import com.iforddow.authservice.auth.utility.TokenHasher;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.InvalidCredentialsException;
import com.iforddow.authservice.common.exception.ResourceNotFoundException;
import com.iforddow.authservice.common.service.SmsService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * A service class for user login methods.
 *
 * @author IFD
 * @since 2025-10-27
 * */
@RequiredArgsConstructor
@Service
public class LoginService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final RedisRefreshTokenService redisRefreshTokenService;
    private final TokenHasher tokenHasher;

    @Value("${auth.max.sessions}")
    private int MAX_CONCURRENT_SESSIONS;

    private final SmsService smsService;

    /**
     * A method to handle user login.
     *
     * @param loginRequest The request object containing user login details.
     * @author IFD
     * @since 2025-10-27
     */
    @Transactional
    public LoginDTO authenticate(LoginRequest loginRequest, HttpServletResponse response) {

        // Ensure device type is valid
        if(!(loginRequest.getDeviceType() == DeviceType.WEB) && !loginRequest.getDeviceType().equals(DeviceType.MOBILE)) {
            throw new BadRequestException("Invalid device type");
        }

        // Ensure user exists
        User user = userRepository.findUserByEmail(loginRequest.getEmail()).orElseThrow(
                () -> new ResourceNotFoundException("User email not found")
        );

        // Try to authenticate user
        try {

            // Perform authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Revoke existing refresh token if provided
            // This is useful if somehow the user hits the login endpoint
            // while already logged in on the same device
            if(loginRequest.getExistingRefreshToken() != null && !loginRequest.getExistingRefreshToken().isEmpty())  {

                // Hash the existing refresh token
                String existingToken = tokenHasher.hmacSha256(loginRequest.getExistingRefreshToken());

                // Revoke the existing token
                redisRefreshTokenService.revokeToken(existingToken);
            }

            // Get all valid tokens for the user
            Set<String> validTokens = redisRefreshTokenService.getValidTokensForUser(user.getId());

            // If user has reached max concurrent sessions, revoke the oldest tokens
            if(validTokens.size() >= MAX_CONCURRENT_SESSIONS) {
                int tokensToRevoke = validTokens.size() - MAX_CONCURRENT_SESSIONS + 1;

                redisRefreshTokenService.revokeOldestTokens(user.getId(), tokensToRevoke);
            }

            // Create new tokens based on device type
            // We do this because web only needs refresh cookie
            // whereas mobile needs both access and refresh tokens in response body
            try {
                if(loginRequest.getDeviceType().equals(DeviceType.WEB)) {
                    tokenService.createNewTokens(response, user, DeviceType.WEB);
                    return null;
                } else {
                    return tokenService.createNewTokens(response, user, DeviceType.MOBILE);
                }
            } catch (AuthenticationException e) {
                throw new BadRequestException("Token generation failed: " + e.getMessage());
            } finally {
                // Send login notification SMS
                try {
                    smsService.sendSms("+19023936781", "Test message");
                } catch (Exception e) {
                    // Log the SMS sending failure but do not interrupt the login process
                    System.err.println("Failed to send SMS notification: " + e.getMessage());
                }
            }

        } catch (AuthenticationException ex) {

            // Handle invalid credentials
            if (ex instanceof BadCredentialsException) {
                throw new InvalidCredentialsException("Invalid credentials provided");
            }
            // Log or return the specific error
            throw new BadRequestException("Authentication failed: " + ex.getMessage());
        }

    }


}
