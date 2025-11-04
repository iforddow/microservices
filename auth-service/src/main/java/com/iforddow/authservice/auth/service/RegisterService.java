package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.common.service.RabbitSenderService;
import com.iforddow.authservice.auth.bo.AuthBO;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.RegisterRequest;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.ResourceExistsException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
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
    private final RabbitSenderService rabbitSenderService;

    /**
     * A method to handle user registration.
     *
     * @param registerRequest The request object containing user registration details.
     * @author IFD
     * @since 2025-06-14
     */
    public void register(RegisterRequest registerRequest, HttpServletResponse response) {

        AuthBO authBO = new AuthBO();

        ArrayList<String> errors = authBO.validateUserRegistration(registerRequest);

        if (!errors.isEmpty()) {
            throw new BadRequestException("Registration failed: " + String.join(", ", errors));
        }

        // Check to ensure the user doesn't exist
        Optional<User> existingUser = userRepository.findUserByEmail(registerRequest.getEmail());

        // If a user with the same email already exists, throw an exception
        if (existingUser.isPresent()) {
            throw new ResourceExistsException("A user with this email already exists");
        }

        // Create a new user
        User user = User.builder()
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .build();

        // Save the new user to the database
        userRepository.save(user);

        // Send a message to RabbitMQ about the new user registration
        rabbitSenderService.sendNewAccountMessage(user.getId().toString());

    }


}
