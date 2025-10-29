package com.iforddow.authservice.auth.dto;

public record LoginDTO(String accessToken, String refreshToken) {

    public LoginDTO(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

}
