package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.application.events.RegistrationEvent;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.RegisterRequest;
import com.iforddow.authservice.auth.validator.RegistrationValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
    private final RegistrationValidator registrationValidator;

    /**
     * A method to handle user registration.
     *
     * @param registerRequest The request object containing user registration details.
     * @author IFD
     * @since 2025-06-14
     */
    @Transactional
    public void register(RegisterRequest registerRequest, String existingToken, HttpServletRequest httpRequest) {

        // Validate the registration details
        registrationValidator.validateRegistrationRequest(registerRequest, existingToken);

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
        eventPublisher.publishEvent(new RegistrationEvent(user, httpRequest));

    }


}
