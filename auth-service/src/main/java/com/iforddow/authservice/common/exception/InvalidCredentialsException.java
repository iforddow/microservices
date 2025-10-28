package com.iforddow.authservice.common.exception;

/**
 * InvalidCredentialsException - An exception that should be thrown
 * when a user submits invalid sign in credentials.
 *
 * @author IFD
 * @since 2025-10-27
 * */
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) {
        super(message);
    }
}
