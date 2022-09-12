package com.kuehnenagel.authorization.service.impl;

import com.kuehnenagel.authorization.common.constant.ErrorEnum;
import com.kuehnenagel.authorization.common.exception.BusinessException;
import com.kuehnenagel.authorization.dao.UserRepository;
import com.kuehnenagel.authorization.dto.model.User;
import com.kuehnenagel.authorization.entity.UserEntity;
import com.kuehnenagel.authorization.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class IUserService implements UserService {

    private final UserRepository userRepository;

    @Override
    public User retrieveUserByUsername(String username) {
        UserEntity existUserEntity = userRepository.findByUsername(username)
                .orElseThrow(() -> new BusinessException(ErrorEnum.USER_NOT_FOUND_ERROR.getCode(), ErrorEnum.USER_NOT_FOUND_ERROR.getMessage()));
        return User.convertUserEntityToUser(existUserEntity);
    }
}
