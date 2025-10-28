package com.iforddow.authservice.common.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
* A mail service class to initialize sending emails
* from the app.
*
* @author IFD
* @since 2025-10-27
* */
@Service
@RequiredArgsConstructor
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${mail.sender}")
    private String emailSender;

    /**
    * A method to send an email
    *
    * @author IFD
    * @since 2025-10-27
    * */
    public void sendMail(String to, String subject, String content) {

        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom(emailSender);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(content);

        mailSender.send(message);

    }

}
