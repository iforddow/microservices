package com.iforddow.authservice.auth.request;

import lombok.Data;

/**
* A request class to provide data needed
* to log in.
*
* @author IFD
* @since 2025-10-27
* */
@Data
public class LoginRequest {

    private String email;
    private String password;
    private String deviceType;

}
