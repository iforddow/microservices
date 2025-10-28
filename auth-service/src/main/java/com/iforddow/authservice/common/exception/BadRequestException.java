package com.iforddow.authservice.common.exception;

/**
* BadRequestException - An exception that should be thrown
* when a user submits a malformed, bad, or incorrect format.
*
* @author IFD
* @since 2025-10-27
* */
public class BadRequestException extends RuntimeException {
    public BadRequestException(String message) {
        super(message);
    }
}
