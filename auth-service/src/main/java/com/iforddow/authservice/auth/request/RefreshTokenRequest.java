package com.iforddow.authservice.auth.request;

import lombok.Data;

/**
* A data class containing the variables to make
* a refresh token request.
*
* @author IFD
* @since 2025-10-27
* */
@Data
public class RefreshTokenRequest {

    private String refreshToken;
    private String deviceType;

}
