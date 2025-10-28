package com.iforddow.authservice.application.templates;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

/**
* A class to initialize a Redis template.
*
* @author IFD
* @since 2025-10-27
* */
@Configuration
@RequiredArgsConstructor
public class RedisObjectTemplate {

    /**
    * A bean to initialize a redis template.
    *
    * @author IFD
    * @since 2025-10-27
    * */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {

        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        return redisTemplate;

    }

}
