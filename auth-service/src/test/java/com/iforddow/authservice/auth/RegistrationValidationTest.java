package com.iforddow.authservice.auth;

import com.iforddow.authservice.auth.bo.AuthBO;
import com.iforddow.authservice.auth.request.RegisterRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Registration Validation Tests")
public class RegistrationValidationTest {

    private AuthBO authBO;

    @BeforeEach
    void setUp() {
        authBO = new AuthBO();
    }

    @Test
    @DisplayName("Registration Validation Test")
    public void registrationValidationTestSuccess_1() {

        RegisterRequest registerRequest = new RegisterRequest();

        registerRequest.setEmail("izaak@email.com");
        registerRequest.setPassword("ABcd123!");
        registerRequest.setConfirmPassword("ABcd123!");

        assert(authBO.validateUserRegistration(registerRequest).isEmpty());

    }

    @Test
    @DisplayName("Registration Validation Test")
    public void registrationValidationTestSuccess_2() {

        RegisterRequest registerRequest = new RegisterRequest();

        registerRequest.setEmail("riley@gmail.com");
        registerRequest.setPassword("FranklinTheTurtle1@");
        registerRequest.setConfirmPassword("FranklinTheTurtle1@");

        assert(authBO.validateUserRegistration(registerRequest).isEmpty());

    }

    @Test
    @DisplayName("Registration Error Test")
    public void registrationValidationError_1() {

        RegisterRequest registerRequest = new RegisterRequest();

        registerRequest.setEmail("riley@gmail..com");
        registerRequest.setPassword("FranklinTheTurtle1@");
        registerRequest.setConfirmPassword("FranklinTheTurtle1@");

        assert(!authBO.validateUserRegistration(registerRequest).isEmpty());

    }

    @Test
    @DisplayName("Registration Error Test")
    public void registrationValidationError_2() {

        RegisterRequest registerRequest = new RegisterRequest();

        registerRequest.setEmail("riley@gmail.com");
        registerRequest.setPassword("FranklinTheTurtle1@");
        registerRequest.setConfirmPassword("RjTheFox1*");

        assert(!authBO.validateUserRegistration(registerRequest).isEmpty());

    }

}
