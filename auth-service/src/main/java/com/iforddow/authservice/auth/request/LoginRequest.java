package com.iforddow.authservice.auth.request;

import com.iforddow.authservice.auth.utility.DeviceType;
import lombok.Data;
import org.springframework.lang.Nullable;

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
    private DeviceType deviceType;

}
