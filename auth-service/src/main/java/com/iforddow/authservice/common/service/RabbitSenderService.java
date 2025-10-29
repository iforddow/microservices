package com.iforddow.authservice.common.service;

import com.iforddow.authservice.common.config.RabbitConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

/**
* A service for sending messages to RabbitMQ queues.
*
* @author IFD
* @since 2025-10-29
* */
@RequiredArgsConstructor
@Service
public class RabbitSenderService {

    private final RabbitTemplate rabbitTemplate;

    /**
    * A method to send a message to the new account queue.
    *
    * @author IFD
    * @since 2025-10-29
    * */
    public void sendNewAccountMessage(String message) {
        rabbitTemplate.convertAndSend(
                RabbitConfig.NEW_ACCOUNT_EXCHANGE,
                RabbitConfig.NEW_ACCOUNT_ROUTING_KEY,
                message
        );
    }

    /**
    * A method to send a message to the deleted account queue.
    *
    * @author IFD
    * @since 2025-10-29
    * */
    public void sendDeletedAccountMessage(String message) {
        rabbitTemplate.convertAndSend(
                RabbitConfig.DELETED_ACCOUNT_EXCHANGE,
                RabbitConfig.DELETED_ACCOUNT_ROUTING_KEY,
                message
        );
    }
}
