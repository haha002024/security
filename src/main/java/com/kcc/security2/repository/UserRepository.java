package com.kcc.security2.repository;

import com.kcc.security2.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    //  findByUsername 정해진 이름이다. 하나의 쿼리가 된다.
    public User findByUsername(String username);

}
