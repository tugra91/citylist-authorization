package com.kuehnenagel.authorization.config.filter;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class KuehneBasicAuthenticationFilter extends BasicAuthenticationFilter {

    private final BasicAuthenticationConverter authenticationConverter;

    public KuehneBasicAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint) {
        super(authenticationManager, authenticationEntryPoint);
        this.authenticationConverter = new BasicAuthenticationConverter();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (new AntPathRequestMatcher("/oauth2/token", HttpMethod.POST.name()).matches(request)) {
            chain.doFilter(request, response);
        } else {
            try {

                UsernamePasswordAuthenticationToken authentication = authenticationConverter.convert(request);

                if (ObjectUtils.isEmpty(authentication)) {
                    chain.doFilter(request, response);
                    return;
                }

                String username = authentication.getName();

                if (authenticationIsRequired(username)) {
                    Authentication authenticateResult = getAuthenticationManager().authenticate(authentication);
                    SecurityContextHolder.getContext().setAuthentication(authenticateResult);
                    this.onSuccessfulAuthentication(request, response, authenticateResult);
                }

            } catch (AuthenticationException ex) {
                SecurityContextHolder.clearContext();
                onUnsuccessfulAuthentication(request, response, ex);
                getAuthenticationEntryPoint().commence(request, response, ex);
                return;
            }

            chain.doFilter(request, response);
        }
    }

    private boolean authenticationIsRequired(String username) {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (ObjectUtils.isNotEmpty(existingAuth)
                && existingAuth.isAuthenticated()) {
            if (existingAuth instanceof UsernamePasswordAuthenticationToken
                    && !StringUtils.equalsAnyIgnoreCase(existingAuth.getName(), username)) {
                return true;
            }
            return existingAuth instanceof AnonymousAuthenticationToken;
        }
        return true;
    }
}
