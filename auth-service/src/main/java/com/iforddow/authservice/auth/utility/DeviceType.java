package com.iforddow.authservice.auth.utility;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;

@Getter
public enum DeviceType {
    WEB("web"),
    MOBILE("mobile");

    private final String type;

    DeviceType(String type) {
        this.type = type;
    }

    @JsonCreator
    public static DeviceType fromString(String text) {
        for(DeviceType deviceType : DeviceType.values()) {
            if(deviceType.type.equalsIgnoreCase(text)) {
                return deviceType;
            }
        }
        throw new IllegalArgumentException("No constant with text " + text + " found");
    }

    @Override
    public String toString() {
        return type;
    }

}
