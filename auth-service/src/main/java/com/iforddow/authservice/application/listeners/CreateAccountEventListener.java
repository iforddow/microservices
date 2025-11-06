package com.iforddow.authservice.application.listeners;

import com.iforddow.authservice.application.events.CreateAccountEvent;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.common.service.MailService;
import com.iforddow.authservice.common.service.RabbitSenderService;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.MailException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@RequiredArgsConstructor
@Component
@Slf4j
public class CreateAccountEventListener {

    private final RabbitSenderService rabbitSenderService;
    private final MailService mailService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleCreateAccountEvent(CreateAccountEvent event) {

        User user = event.user();

        // Send message to other services about new account — log failures but do not throw
        rabbitSenderService.sendNewAccountMessage(user.getId().toString());

        try {
            mailService.sendNewAccountEmail(user.getEmail(), "https://auth.iforddow.com/login");
        } catch (MessagingException e) {
            log.error("Failed to send new account email to {}: {}", user.getEmail(), e.getMessage());
        } catch (MailException e) {
            log.error("Mail service error when sending new account email to {}: {}", user.getEmail(), e.getMessage());
        }

    }

}
