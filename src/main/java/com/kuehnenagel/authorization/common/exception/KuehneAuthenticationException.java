package com.kuehnenagel.authorization.common.exception;

import org.springframework.security.core.AuthenticationException;

import java.io.Serial;

public class KuehneAuthenticationException extends AuthenticationException {


    @Serial
    private static final long serialVersionUID = 3478330184684493234L;

    public KuehneAuthenticationException(String msg) {
        super(msg);
    }
}
