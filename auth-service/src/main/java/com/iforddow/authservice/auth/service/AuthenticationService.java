package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.LoginRequest;
import com.iforddow.authservice.auth.request.RefreshTokenRequest;
import com.iforddow.authservice.auth.utility.DeviceType;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.InvalidCredentialsException;
import com.iforddow.authservice.common.exception.ResourceNotFoundException;
import com.iforddow.authservice.common.exception.UnauthorizedException;
import com.iforddow.authservice.common.security.JwtService;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
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
    private final TokenService tokenService;
    private final RedisRefreshTokenService redisRefreshTokenService;
    private final JwtService jwtService;

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

            // Revoke existing refresh token if provided
            // This is useful if somehow the user hits the login endpoint
            // while already logged in on the same device
            if(AuthServiceUtility.isNullOrEmpty(existingToken))  {

                // Hash the existing refresh token
                String existingTokenHashed = tokenService.hmacSha256(existingToken);

                // Revoke the existing token
                redisRefreshTokenService.revokeToken(existingTokenHashed);
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
                String token = tokenService.createNewTokens(user, loginRequest.getDeviceType(), response);

//                smsService.sendSms("+19023936781",
//                        "User " + user.getEmail() + " has logged in on "
//                                 + loginRequest.getDeviceType().toString() + " device.",
//                        false);

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
        }

    }

    /**
     * A method to handle token refresh requests.
     *
     * @param refreshTokenRequest The refresh token request.
     * @return ResponseEntity containing the new access token if refresh is successful.
     * @author IFD
     * @since 2025-06-15
     */
    public String refreshToken(RefreshTokenRequest refreshTokenRequest, HttpServletResponse response) {

        if(!(refreshTokenRequest.getDeviceType() == DeviceType.WEB) && !refreshTokenRequest.getDeviceType().equals(DeviceType.MOBILE)) {
            throw new BadRequestException("Invalid device type");
        }

        String refreshToken = refreshTokenRequest.getRefreshToken();

        if(!jwtService.validateJwtToken(refreshToken)) {
            throw new UnauthorizedException("Invalid token");
        }

        String hashedRefreshToken = tokenService.hmacSha256(refreshToken);

        UUID userId = redisRefreshTokenService.getUserIdFromToken(hashedRefreshToken);

        if(userId == null) {
            throw new BadRequestException("User id not found for the provided token");
        }

        User user = userRepository.findById(userId).orElseThrow(
                () -> new ResourceNotFoundException("User not found in database")
        );

        redisRefreshTokenService.revokeToken(hashedRefreshToken);

        if(refreshTokenRequest.getDeviceType() == DeviceType.WEB) {
            tokenService.createNewTokens(user, DeviceType.WEB, response);
            return null;
        } else {
            return tokenService.createNewTokens(user, DeviceType.MOBILE, response);
        }

    }



}
