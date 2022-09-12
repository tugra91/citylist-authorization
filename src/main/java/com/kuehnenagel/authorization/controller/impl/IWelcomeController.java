package com.kuehnenagel.authorization.controller.impl;

import com.kuehnenagel.authorization.controller.WelcomeContoller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IWelcomeController implements WelcomeContoller {

    @GetMapping(value = "/welcome/getCode")
    @Override
    public String bounceCode(@RequestParam("code") String code) {
        return code;
    }
}
