package com.kuehnenagel.authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;

@EnableAutoConfiguration
@ComponentScan(basePackages = {"com.kuehnenagel.authorization"})
public class KuehneAuthenticationApp {

    public static void main(String[] args) {
        SpringApplication.run(KuehneAuthenticationApp.class, args);
    }
}
