package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.common.exception.ResourceNotFoundException;
import com.iforddow.authservice.common.service.RabbitSenderService;
import lombok.RequiredArgsConstructor;
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
    private final RabbitSenderService rabbitSenderService;

    /**
    * A method to delete a user account by user ID.
    *
    * @param userId The UUID of the user to be deleted.
    *
    * @author IFD
    * @since 2025-10-29
    * */
    public void deleteAccount(UUID userId) {

        User user = userRepository.findById(userId).orElseThrow(
                () -> new ResourceNotFoundException("User not found with id: " + userId)
        );

        userRepository.delete(user);

        rabbitSenderService.sendDeletedAccountMessage(userId.toString());


    }

}
