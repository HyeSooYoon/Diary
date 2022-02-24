package com.diary.em.Repository;

import com.diary.em.Entity.Person;

import org.springframework.data.repository.CrudRepository;

public interface PersonRedisRepository extends CrudRepository<Person, String> {
    
}
