package com.iforddow.authservice.auth.controller;

import com.iforddow.authservice.auth.request.*;
import com.iforddow.authservice.auth.service.*;
import com.iforddow.authservice.common.security.JwtService;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * A controller class to handle authentication
 * endpoints.
 *
 * @author IFD
 * @since 2025-10-27
 *
 */
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final RegisterService registerService;
    private final AuthenticationService authenticationService;
    private final DeleteAccountService deleteAccountService;
    private final LogoutService logoutService;
    private final TokenService tokenService;
    private final PasswordService passwordService;
    private final JwtService jwtService;

    /**
     * An endpoint for accessing the registration method.
     *
     * @author IFD
     * @since 2025-10-28
     *
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(
            @CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody RegisterRequest registerRequest, HttpServletResponse response) {

        String existingToken = tokenService.ensureOneToken(cookieValue, authHeader);

        try {
            registerService.register(registerRequest, existingToken, response);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }

    /**
     * An endpoint for accessing the authentication (login) method.
     *
     * @author IFD
     * @since 2025-10-28
     *
     */
    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(
            @CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse response) {

        String existingToken = tokenService.ensureOneToken(cookieValue, authHeader);

        try {
            String loginResult = authenticationService.authenticate(loginRequest, existingToken, response);
            return ResponseEntity.ok(loginResult);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }

    }

    /**
    * An endpoint for accessing the logout method.
    *
    * @author IFD
    * @since 2025-11-02
    * */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody LogoutRequest logoutRequest, HttpServletResponse response) {

        String existingToken = tokenService.ensureOneToken(cookieValue, authHeader);

        try {
            logoutService.logout(logoutRequest, existingToken, response);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }

    /**
    * A controller endpoint for accessing the token refresh method.
    *
    * @author IFD
    * @since 2025-11-02
    * */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            @CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest, HttpServletResponse response) {

        // Make sure the refresh token request is valid
        if (refreshTokenRequest == null) {
            return ResponseEntity.badRequest().body("Refresh token and device type is required");
        }

        // If there is an existing refresh token cookie, set it in the refresh token request
        // Only for Web scenarios where mobile apps won't have cookies so the refresh token
        // is already expected to be in the request body
        if(!AuthServiceUtility.isNullOrEmpty(cookieValue)) {
            refreshTokenRequest.setRefreshToken(cookieValue);
        }

        // Make sure the refresh token is present
        if(refreshTokenRequest.getRefreshToken() == null) {
            return ResponseEntity.badRequest().body("Existing refresh token was not found");
        }

        try {
            String refreshResult = authenticationService.refreshToken(refreshTokenRequest, response);

            return ResponseEntity.ok(refreshResult);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    /**
     * An endpoint for accessing the delete account method.
     *
     * @author IFD
     * @since 2025-10-29
     *
     */
    @DeleteMapping("/delete")
    public ResponseEntity<?> deleteAccount(@CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
                                           @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if(!AuthServiceUtility.isNullOrEmpty(cookieValue)) {
                deleteAccountService.deleteAccount(cookieValue);
            } else if(!AuthServiceUtility.isNullOrEmpty(authHeader)) {
                deleteAccountService.deleteAccount(authHeader);
            } else {
                return ResponseEntity.badRequest().body("No authentication method provided");
            }

            return ResponseEntity.ok().body("User deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }

    /**
    * An endpoint to change a user's password.
    *
    * @author IFD
    * @since 2025-11-02
    * */
    @PostMapping("/change-password")
    public ResponseEntity<?> changeAccountPassword(@CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
                                                   @RequestHeader(value = "Authorization", required = false) String authHeader,
                                                   @RequestBody ChangePasswordRequest changePasswordRequest) {

        jwtService.getUserIdFromToken(authHeader);

        try {
            passwordService.changeUserPassword(changePasswordRequest);
            return ResponseEntity.ok().body("Password changed successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Unable to change password: " + e.getMessage());
        }

    }
}
