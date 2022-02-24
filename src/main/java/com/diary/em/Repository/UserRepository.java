package com.diary.em.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

import com.diary.em.Entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
}