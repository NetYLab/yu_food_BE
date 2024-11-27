package com.example.demo.repository;

import java.util.List;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.example.demo.entity.Menu;
import com.example.demo.entity.Restaurant;

@Repository
public interface MenuRepository extends JpaRepository<Menu, Integer> {
    
	// fetch join을 사용한 메소드
    @Query("SELECT m FROM Menu m JOIN FETCH m.restaurant r WHERE r.rid = :rid")
    List<Menu> findByRestaurantIdWithFetchJoin(@Param("rid") Integer rid);
}