package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.SessionTokenRequest;
import com.iforddow.authservice.auth.request.LoginRequest;
import com.iforddow.authservice.auth.utility.DeviceType;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.InvalidCredentialsException;
import com.iforddow.authservice.common.exception.ResourceNotFoundException;
import com.iforddow.authservice.common.exception.UnauthorizedException;
import com.iforddow.authservice.common.security.JwtService;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import com.iforddow.authservice.common.utility.HashUtil;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.UUID;

/**
 * A service class for user login methods.
 *
 * @author IFD
 * @since 2025-10-27
 * */
@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final SessionTokenService sessionTokenService;
    private final RedisSessionTokenService redisSessionTokenService;
    private final JwtService jwtService;
    private final HashUtil hashUtil;

    @Value("${auth.max.sessions}")
    private int MAX_CONCURRENT_SESSIONS;

    /**
     * A method to handle user login.
     *
     * @param loginRequest The request object containing user login details.
     * @author IFD
     * @since 2025-10-27
     */
    public String authenticate(LoginRequest loginRequest, String existingToken, HttpServletResponse response) {

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

            // Revoke existing session token if provided
            // This is useful if somehow the user hits the login endpoint
            // while already logged in on the same device
            if(!AuthServiceUtility.isNullOrEmpty(existingToken))  {

                // Hash the existing session token
                String existingTokenHashed = hashUtil.hmacSha256(existingToken);

                // Revoke the existing token
                redisSessionTokenService.revokeToken(existingTokenHashed);
            }

            // Get all valid tokens for the user
            Set<String> validTokens = redisSessionTokenService.getValidTokensForUser(user.getId());

            // If user has reached max concurrent sessions, revoke the oldest tokens
            if(validTokens.size() >= MAX_CONCURRENT_SESSIONS) {
                int tokensToRevoke = validTokens.size() - MAX_CONCURRENT_SESSIONS + 1;

                redisSessionTokenService.revokeOldestTokens(user.getId(), tokensToRevoke);
            }

            // Create new tokens based on device type
            try {
                String token = sessionTokenService.createNewTokens(user, loginRequest.getDeviceType(), response);

                if(loginRequest.getDeviceType().equals(DeviceType.WEB)) {
                    return null;
                } else {
                    return token;
                }

            } catch (AuthenticationException e) {
                throw new BadRequestException("Token generation failed: " + e.getMessage());
            }

        } catch (AuthenticationException ex) {

            // Handle invalid credentials
            if (ex instanceof BadCredentialsException) {
                throw new InvalidCredentialsException("Invalid credentials provided");
            }
            // Log or return the specific error
            throw new BadRequestException("Authentication failed: " + ex.getMessage());
        } catch (Exception e) {
            throw new BadRequestException("Authentication error: " + e.getMessage());
        }

    }

    /**
     * A method to handle session token refresh requests.
     *
     * @param sessionTokenRequest The session token request.
     * @return ResponseEntity containing the new session token if refresh is successful.
     * @author IFD
     * @since 2025-06-15
     */
    public String refreshSessionToken(SessionTokenRequest sessionTokenRequest, HttpServletResponse response) {

        if(!(sessionTokenRequest.getDeviceType() == DeviceType.WEB) && !sessionTokenRequest.getDeviceType().equals(DeviceType.MOBILE)) {
            throw new BadRequestException("Invalid device type");
        }

        String sessionToken = sessionTokenRequest.getSessionToken();

        if(!jwtService.validateJwtToken(sessionToken)) {
            throw new UnauthorizedException("Invalid token");
        }

        String hashedSessionToken = hashUtil.hmacSha256(sessionToken);

        UUID userId = redisSessionTokenService.getUserIdFromToken(hashedSessionToken);

        if(userId == null) {
            throw new BadRequestException("User id not found for the provided token");
        }

        User user = userRepository.findById(userId).orElseThrow(
                () -> new ResourceNotFoundException("User not found in database")
        );

        redisSessionTokenService.revokeToken(hashedSessionToken);

        if(sessionTokenRequest.getDeviceType() == DeviceType.WEB) {
            sessionTokenService.createNewTokens(user, DeviceType.WEB, response);
            return null;
        } else {
            return sessionTokenService.createNewTokens(user, DeviceType.MOBILE, response);
        }

    }



}
