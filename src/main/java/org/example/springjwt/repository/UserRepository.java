package org.example.springjwt.repository;


import org.apache.catalina.User;
import org.example.springjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer > {

    Boolean existsByUsername(String username);
}
