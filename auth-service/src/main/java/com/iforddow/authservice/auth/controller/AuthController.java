package com.iforddow.authservice.auth.controller;

import com.iforddow.authservice.auth.request.*;
import com.iforddow.authservice.auth.service.*;
import com.iforddow.authservice.common.service.GeoLocationService;
import com.iforddow.authservice.common.security.JwtService;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class AuthController {

    private final RegisterService registerService;
    private final AuthenticationService authenticationService;
    private final DeleteAccountService deleteAccountService;
    private final LogoutService logoutService;
    private final SessionTokenService sessionTokenService;
    private final PasswordService passwordService;
    private final JwtService jwtService;
    private final GeoLocationService geoLocationService;

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
            @RequestBody RegisterRequest registerRequest,
            HttpServletRequest httpRequest) {

        // Ensure there is only one session token from either cookie or header
        String existingToken = sessionTokenService.ensureOneToken(cookieValue, authHeader);

        registerService.register(registerRequest, existingToken, httpRequest);

        return ResponseEntity.ok().build();

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

        String existingToken = sessionTokenService.ensureOneToken(cookieValue, authHeader);

        String loginResult = authenticationService.authenticate(loginRequest, existingToken, response);
        return ResponseEntity.ok(loginResult);

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

        String existingToken = sessionTokenService.ensureOneToken(cookieValue, authHeader);

        try {
            logoutService.logout(logoutRequest, existingToken, response);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }

    /**
    * A controller endpoint for accessing the session token refresh method.
    *
    * @author IFD
    * @since 2025-11-02
    * */
    @PostMapping("/session/refresh")
    public ResponseEntity<?> sessionRefresh(
            @CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
            @RequestBody(required = false) SessionTokenRequest sessionTokenRequest, HttpServletResponse response) {

        // Make sure the session token request is valid
        if (sessionTokenRequest == null) {
            return ResponseEntity.badRequest().body("Session token and device type is required");
        }

        // If there is an existing session token cookie, set it in the session token request
        // Only for Web scenarios where mobile apps won't have cookies so the session token
        // is already expected to be in the request body
        if(!AuthServiceUtility.isNullOrEmpty(cookieValue)) {
            sessionTokenRequest.setSessionToken(cookieValue);
        }

        // Make sure the session token is present
        if(sessionTokenRequest.getSessionToken() == null) {
            return ResponseEntity.badRequest().body("Existing session token was not found");
        }

        try {
            String refreshSessionResult = authenticationService.refreshSessionToken(sessionTokenRequest, response);

            return ResponseEntity.ok(refreshSessionResult);
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

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
