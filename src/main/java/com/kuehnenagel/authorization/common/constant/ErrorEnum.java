package com.kuehnenagel.authorization.common.constant;

public enum ErrorEnum {

    ATTEMPT_UNAUTHORIZATION_ACTIVITY_ERROR("-1", "It was blocked due to attempted unauthorization operation."),
    USER_NOT_FOUND_ERROR("-2", "User doesn't exists."),
    WRONG_PASSWORD_ERROR("-3", "Incorrect Password. Please try to type correct one.");

    private final String code;
    private final String message;

    ErrorEnum(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
