package com.iforddow.authservice.common.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
* Configuration for auth-service WebConfig.
*
* @author IFD
* @since 2025-10-27
* */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
    * Override default path. Adding a simple prefix of "/api/auth"
    *
    * @author IFD
    * @since 2025-10-27
    * */
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.addPathPrefix("/api/auth", c -> c.isAnnotationPresent(RestController.class));
    }

}
