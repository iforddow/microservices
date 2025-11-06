package com.iforddow.authservice.application.events;

import com.iforddow.authservice.auth.entity.User;

public record CreateAccountEvent(User user) {
}
