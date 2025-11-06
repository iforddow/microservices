package com.iforddow.authservice.application.listeners;

import com.iforddow.authservice.application.events.DeleteAccountEvent;
import com.iforddow.authservice.auth.service.RedisRefreshTokenService;
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
    private final RedisRefreshTokenService redisRefreshTokenService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleDeleteAccountEvent(DeleteAccountEvent event) {
        UUID userId = event.userId();

        // Send message to other services about account deletion
        rabbitSenderService.sendDeletedAccountMessage(userId.toString());

        // Revoke all refresh tokens associated with the user
        redisRefreshTokenService.revokeAllTokensForUser(userId);
    }

}
