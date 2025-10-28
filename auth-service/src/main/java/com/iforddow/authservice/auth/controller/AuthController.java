package com.iforddow.authservice.auth.controller;

import com.iforddow.authservice.auth.request.LoginRequest;
import com.iforddow.authservice.auth.request.RegisterRequest;
import com.iforddow.authservice.auth.service.LoginService;
import com.iforddow.authservice.auth.service.RegisterService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

/**
* A controller class to handle authentication
* endpoints.
*
* @author IFD
* @since 2025-10-27
* */
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final RegisterService registerService;
    private final LoginService  loginService;

    /**
    * An endpoint for accessing the registration method.
    *
    * @author IFD
    * @since 2025-10-28
    * */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody(required = false) RegisterRequest registerRequest, HttpServletResponse response) {

        if(registerRequest == null) {
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
    * */
    @PostMapping("authenticate")
    public ResponseEntity<Optional<Map<String, String>>> authenticate(@RequestBody(required = false) LoginRequest loginRequest, HttpServletResponse response) {

        if(loginRequest == null) {
            return ResponseEntity.badRequest().body(Optional.of(Map.of("message", "Invalid login request")));
        }

        try {
            Optional<Map<String, String>> loginResult = loginService.authenticate(loginRequest, response);

            if(loginResult.isPresent()) {
                return  ResponseEntity.ok(loginResult);
            }   else {
                return ResponseEntity.ok().build();
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Optional.of(Map.of("message", e.getMessage())));
        }

    }

}
