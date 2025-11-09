package com.iforddow.authservice.application.listeners;

import com.iforddow.authservice.application.events.DeleteAccountEvent;
import com.iforddow.authservice.auth.service.RedisSessionTokenService;
import com.iforddow.authservice.common.service.RabbitSenderService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.UUID;

@RequiredArgsConstructor
@Component
public class DeleteAccountEventListener {

    private final RabbitSenderService rabbitSenderService;
    private final RedisSessionTokenService redisSessionTokenService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleDeleteAccountEvent(DeleteAccountEvent event) {
        UUID userId = event.userId();

        // Send message to other services about account deletion
        rabbitSenderService.sendDeletedAccountMessage(userId.toString());

        // Revoke all session tokens associated with the user
        redisSessionTokenService.revokeAllTokensForUser(userId);
    }

}
