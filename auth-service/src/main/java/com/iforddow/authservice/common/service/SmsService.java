package com.iforddow.authservice.common.service;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SmsService {

    @Value("${twilio.phone.number}")
    private String fromNumber;

    public void sendSms(String phoneNumber, String message) {

        if(AuthServiceUtility.isNullOrEmpty(phoneNumber) || AuthServiceUtility.isNullOrEmpty(message)) {
            return;
        }

        Message.creator(new PhoneNumber(phoneNumber), new PhoneNumber(fromNumber), message).create();

    }

}
