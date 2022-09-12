package com.kuehnenagel.authorization.config;


import com.kuehnenagel.authorization.config.filter.KuehneBasicAuthenticationEntryPoint;
import com.kuehnenagel.authorization.config.filter.KuehneBasicAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@RequiredArgsConstructor
public class EndpointSecurityConfiguration {

    private final KuehneAuthenticationManager kuehneAuthenticationManager;
    private final KuehneBasicAuthenticationEntryPoint kuehneBasicAuthenticationEntryPoint;

    @Bean
    @Order(10)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        return (SecurityFilterChain) http.httpBasic().and().requestMatcher(endpointsMatcher).authorizeRequests((authorizeRequests) -> {
            ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)authorizeRequests.anyRequest()).authenticated();
        }).csrf((csrf) -> {
            csrf.ignoringRequestMatchers(new RequestMatcher[]{endpointsMatcher});
        }).addFilterBefore(new KuehneBasicAuthenticationFilter(kuehneAuthenticationManager, kuehneBasicAuthenticationEntryPoint), X509AuthenticationFilter.class).apply(authorizationServerConfigurer).and().build();

    }

    @Bean
    @Order(20)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http.httpBasic().and()
                .authorizeRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                );
        // @formatter:on

        return http.build();
    }
}
