package com.iforddow.authservice.auth.controller;

import com.iforddow.authservice.auth.dto.LoginDTO;
import com.iforddow.authservice.auth.request.LoginRequest;
import com.iforddow.authservice.auth.request.LogoutRequest;
import com.iforddow.authservice.auth.request.RegisterRequest;
import com.iforddow.authservice.auth.service.DeleteAccountService;
import com.iforddow.authservice.auth.service.LoginService;
import com.iforddow.authservice.auth.service.LogoutService;
import com.iforddow.authservice.auth.service.RegisterService;
import com.iforddow.authservice.auth.utility.PermissionCheck;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

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
    private final LoginService loginService;
    private final DeleteAccountService deleteAccountService;
    private final LogoutService logoutService;
    private final PermissionCheck permissionCheck;

    /**
     * An endpoint for accessing the registration method.
     *
     * @author IFD
     * @since 2025-10-28
     *
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody(required = false) RegisterRequest registerRequest, HttpServletResponse response) {

        if (registerRequest == null) {
            return ResponseEntity.badRequest().body("Invalid registration request");
        }

        try {
            registerService.register(registerRequest, response);
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
    public ResponseEntity<LoginDTO> authenticate(
            @CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
            @RequestBody(required = false) LoginRequest loginRequest,
            HttpServletResponse response) {

        //Make sure the login request is valid
        if (loginRequest == null) {
            return ResponseEntity.badRequest().build();
        }

        //If there is an existing refresh token cookie, set it in the login request
        //Only for Web scenarios where mobile apps won't have cookies so the refresh token
        //is already expected to be in the request body
        if (!AuthServiceUtility.isNullOrEmpty(cookieValue)) {
            loginRequest.setExistingRefreshToken(cookieValue);
        }

        try {
            LoginDTO loginResult = loginService.authenticate(loginRequest, response);

            return ResponseEntity.ok(loginResult);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }

    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody(required = false) LogoutRequest logoutRequest, HttpServletResponse response) {

        if (logoutRequest == null) {
            return ResponseEntity.badRequest().body("Invalid logout request");
        }

        try {
            logoutService.logout(logoutRequest, response);
            return ResponseEntity.ok().build();
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
    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<?> deleteAccount(@PathVariable String userId,
                                           @CookieValue(value = "${jwt.cookie.name}", required = false) String cookieValue,
                                           @RequestHeader(value = "Authorization", required = false) String authHeader) {

        if(!permissionCheck.checkIsAccountOwner(userId, cookieValue, authHeader)) {
            return ResponseEntity.status(403).body("Access denied: You do not have permission to access this resource");
        }

        try {
            UUID id = UUID.fromString(userId);

            deleteAccountService.deleteAccount(id);
            return ResponseEntity.ok().body("User deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }

}
