package com.iforddow.authservice.auth.utility;

import com.iforddow.authservice.common.security.JwtService;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class PermissionCheck {

    private final JwtService jwtService;

    public boolean checkIsAccountOwner(String expectedId, String tokenValue, String authHeader) {

        String token = null;

        // Get token from cookie (web) or Authorization header (mobile)
        if (!AuthServiceUtility.isNullOrEmpty(tokenValue)) {
            token = tokenValue;
        } else if (!AuthServiceUtility.isNullOrEmpty(authHeader) && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        if (AuthServiceUtility.isNullOrEmpty(token)) {
            return false;
        }

        if(!jwtService.validateJwtToken(token)) {
            return false;
        }

        String userIdFromToken = jwtService.getUserIdFromToken(token);

        return expectedId.equals(userIdFromToken);

    }

}
