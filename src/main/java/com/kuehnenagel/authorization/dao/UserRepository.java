package com.kuehnenagel.authorization.dao;

import com.kuehnenagel.authorization.entity.UserEntity;
import org.bson.types.ObjectId;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, ObjectId> {

    Optional<UserEntity> findByUsername(String username);


}
