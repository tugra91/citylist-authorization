
package com.kuehnenagel.authorization.config;

import com.kuehnenagel.authorization.common.exception.BusinessException;
import com.kuehnenagel.authorization.dto.model.User;
import com.kuehnenagel.authorization.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class KuehneUserDetailsService implements UserDetailsService {

    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User user = userService.retrieveUserByUsername(username);
            return org.springframework.security.core.userdetails.User.withUsername(user.username()).password(user.password()).roles(user.role()).build();
        } catch (BusinessException ex) {
            throw new UsernameNotFoundException(ex.getMessage());
        }
    }
}
