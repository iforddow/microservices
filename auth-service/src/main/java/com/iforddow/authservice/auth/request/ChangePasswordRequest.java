package com.iforddow.authservice.auth.request;

import lombok.Data;

@Data
public class ChangePasswordRequest {

    private String oldPassword;
    private String newPassword;
    private String confirmNewPassword;

}
