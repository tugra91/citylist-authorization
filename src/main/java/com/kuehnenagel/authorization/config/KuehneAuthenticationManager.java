package com.kuehnenagel.authorization.config;

import com.kuehnenagel.authorization.common.constant.ErrorEnum;
import com.kuehnenagel.authorization.common.exception.KuehneAuthenticationException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class KuehneAuthenticationManager implements AuthenticationManager {

    private final UserDetailsService userDetailsService;

    @Qualifier("passwordEncoder")
    private final BCryptPasswordEncoder passwordEncoder;

    @DependsOn("passwordEncoder")
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();

        try {
            UserDetails user = userDetailsService.loadUserByUsername(username);

            if(!passwordEncoder.matches(password, user.getPassword())) {
                throw new KuehneAuthenticationException(ErrorEnum.WRONG_PASSWORD_ERROR.getMessage());
            }

            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        } catch (UsernameNotFoundException ex) {
            throw new KuehneAuthenticationException(ex.getMessage());
        }
    }
}
