package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.application.events.CreateAccountEvent;
import com.iforddow.authservice.auth.bo.AuthBO;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.RegisterRequest;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.ResourceExistsException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;

/**
* A service class for user registration.
*
* @author IFD
* @since 2025-10-27
* */
@RequiredArgsConstructor
@Service
public class RegisterService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final ApplicationEventPublisher eventPublisher;

    /**
     * A method to handle user registration.
     *
     * @param registerRequest The request object containing user registration details.
     * @author IFD
     * @since 2025-06-14
     */
    @Transactional
    public void register(RegisterRequest registerRequest, String existingToken, HttpServletResponse response) {

        // Prevent registration if already logged in
        if(existingToken != null && !existingToken.isEmpty()) {
            throw new BadRequestException("You are already logged into an account, to create a new account, please log out first.");
        }

        // Create an instance of AuthBO to validate registration details
        AuthBO authBO = new AuthBO();

        // Validate the registration details
        ArrayList<String> errors = authBO.validateUserRegistration(registerRequest);

        // If there are validation errors, throw a BadRequestException with the errors
        if (!errors.isEmpty()) {
            throw new BadRequestException("Registration failed: " + String.join(", ", errors));
        }

        // Check to ensure the user doesn't exist
        Optional<User> existingUser = userRepository.findUserByEmail(registerRequest.getEmail());

        // If a user with the same email already exists, throw an exception
        if (existingUser.isPresent()) {
            throw new ResourceExistsException("A user with this email already exists");
        }

        // If we get to this point, all validations have passed, and we
        // are ready to create the new user account.

        // Create a new user
        User user = User.builder()
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .build();

        // Save the new user to the database
        userRepository.save(user);

        // Publish an event to handle post-registration actions (will notify RabbitMQ and send verification email)
        eventPublisher.publishEvent(new CreateAccountEvent(user));

    }


}
