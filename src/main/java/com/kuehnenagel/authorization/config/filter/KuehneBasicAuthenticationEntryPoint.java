package com.kuehnenagel.authorization.config.filter;

import com.google.gson.Gson;
import com.kuehnenagel.authorization.common.constant.ErrorEnum;
import com.kuehnenagel.authorization.common.dto.ErrOutput;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class KuehneBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

    private final Gson gson;
    public KuehneBasicAuthenticationEntryPoint() {
        this.gson = new Gson();
        super.setRealmName("DefaultRealm");
    }

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
        ErrOutput output = new ErrOutput(false, ErrorEnum.ATTEMPT_UNAUTHORIZATION_ACTIVITY_ERROR.getCode(), ErrorEnum.ATTEMPT_UNAUTHORIZATION_ACTIVITY_ERROR.getMessage());
        httpServletResponse.addHeader("WWW-Authenticate", "Basic realm=\"" + super.getRealmName() + "\"");
        httpServletResponse.addHeader("Content-Type", "application/json");
        httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
        httpServletResponse.getOutputStream().print(gson.toJson(output));
    }
}
