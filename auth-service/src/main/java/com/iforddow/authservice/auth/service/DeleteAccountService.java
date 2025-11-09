package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.application.events.DeleteAccountEvent;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.ResourceNotFoundException;
import com.iforddow.authservice.common.security.JwtService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
* A service class for deleting user accounts.
*
* @author IFD
* @since 2025-10-29
* */
@RequiredArgsConstructor
@Service
public class DeleteAccountService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ApplicationEventPublisher eventPublisher;
    private final SessionTokenService sessionTokenService;


    /**
    * A method to delete a user account by user ID.
    *
    * @param authToken The authentication token of the user.
    *
    * @author IFD
    * @since 2025-10-29
    * */
    @Transactional
    public void deleteAccount(String authToken) {

        String token = sessionTokenService.extractTokenFromHeader(authToken);

        if(!jwtService.validateJwtToken(token)) {
            throw new BadRequestException("Invalid JWT token");
        }

        UUID userId = UUID.fromString(jwtService.getUserIdFromToken(token));

        User user = userRepository.findById(userId).orElseThrow(
                () -> new ResourceNotFoundException("User not found with id: " + userId)
        );

        userRepository.delete(user);

        eventPublisher.publishEvent(new DeleteAccountEvent(userId));

    }

}
