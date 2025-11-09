package com.iforddow.authservice.application.events;

import com.iforddow.authservice.auth.entity.User;
import jakarta.servlet.http.HttpServletRequest;

public record RegistrationEvent(User user, HttpServletRequest request) {
}
