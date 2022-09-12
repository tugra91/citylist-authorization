package com.kuehnenagel.authorization.service;

import com.kuehnenagel.authorization.dto.model.User;

public interface UserService {

    User retrieveUserByUsername(String username);
}
