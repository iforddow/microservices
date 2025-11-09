package com.iforddow.authservice.application.listeners;

import com.iforddow.authservice.application.events.RegistrationEvent;
import com.iforddow.authservice.auth.entity.GeoLocation;
import com.iforddow.authservice.auth.entity.RegistrationAudit;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.RegistrationAuditRepository;
import com.iforddow.authservice.common.service.GeoLocationService;
import com.iforddow.authservice.common.utility.HashUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import ua_parser.Client;
import ua_parser.Parser;

import java.time.Instant;

/*
* A listener class to handle adding registration audit records
* upon a new user registration.
*
* @author IFD
* @since 2025-11-09
* */
@RequiredArgsConstructor
@Component
@Slf4j
public class RegistrationAuditListener {

    private final HashUtil hashUtil;
    private final GeoLocationService geoLocationService;
    private final RegistrationAuditRepository registrationAuditRepository;

    /**
     * A method to add a registration audit record after a successful user registration.
     *
     * @param registrationEvent The registration event containing user and request details.
     *
     * @author IFD
     * @since 2025-11-09
     * */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void handleRegistrationEvent(RegistrationEvent registrationEvent) {

        try {
            User user = registrationEvent.user();
            HttpServletRequest request = registrationEvent.request();

            // Hashed user ID
            String userHash = hashUtil.hmacSha256(user.getId().toString());

            String ipAddress = request.getRemoteAddr();

            GeoLocation geoLocation = geoLocationService.getLocation(ipAddress);

            // Get IP address
            String hashedIp = hashUtil.hmacSha256(ipAddress);

            // Parse User-Agent and get required info
            Parser uaParser = new Parser();
            Client agent = uaParser.parse(registrationEvent.request().getHeader("User-Agent"));

            String deviceType = agent.device.family;
            String osType = agent.os.family;
            String osVersion = agent.os.major + "." + agent.os.minor + "." + agent.os.patch;
            String browserType = agent.userAgent.family;
            String browserVersion = agent.userAgent.major + "." + agent.userAgent.minor + "." + agent.userAgent.patch;

            // Create and save RegistrationAudit record
            RegistrationAudit registrationAudit = RegistrationAudit.builder()
                    .userHash(userHash)
                    .ipAddressHash(hashedIp)
                    .country(geoLocation.getCountry())
                    .countryCode(geoLocation.getCountryCode())
                    .region(geoLocation.getCity())
                    .city(geoLocation.getRegion())
                    .deviceType(deviceType)
                    .osType(osType)
                    .osVersion(osVersion)
                    .browserType(browserType)
                    .browserVersion(browserVersion)
                    .timestamp(Instant.now())
                    .build();

            registrationAuditRepository.save(registrationAudit);

            // Log success
            log.info("RegistrationAudit saved for user {}", userHash);

        } catch (Exception e) {
            // Log any errors
            log.error("Failed to log registration audit: {}", e.getMessage());
        }
    }

}
