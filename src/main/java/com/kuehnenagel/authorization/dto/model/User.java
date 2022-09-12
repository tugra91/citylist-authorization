package com.kuehnenagel.authorization.dto.model;

import com.kuehnenagel.authorization.entity.UserEntity;

import java.io.Serial;
import java.io.Serializable;

public record User(String username,
                   String password,
                   String role) implements Serializable {
    @Serial
    private static final long serialVersionUID = 4564572938998113728L;

    public static User convertUserEntityToUser(UserEntity userEntity) {
        return new User(userEntity.username(),userEntity.password(), userEntity.role());
    }
}
