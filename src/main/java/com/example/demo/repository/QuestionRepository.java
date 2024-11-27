package com.example.demo.repository;

import com.example.demo.entity.Question;
import com.example.demo.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface QuestionRepository extends JpaRepository<Question, Long> {
    Question findByTitle(String title);
    Question findByTitleAndContent(String title, String content);
    List<Question> findByTitleLike(String title);
    Page<Question> findByAuthor(User author, Pageable pageable);
    Page<Question> findAll(Pageable pageable);
    Page<Question> findAll(Specification<Question> spec, Pageable pageable);
    @Query("SELECT "
            + "distinct q "
            + "from Question q "
            + "left outer join User u1 on q.author = u1 "
            + "left outer join Answer a on a.question = q "
            + "left outer join User u2 on a.author = u2 "
            + "where "
            + "   q.title like %:keyword% "
            + "   or q.content like %:keyword% "
            + "   or u1.username like %:keyword% "
            + "   or a.content like %:keyword% "
            + "   or u2.username like %:keyword% ")
    Page<Question> findAllByKeyword(@Param("keyword") String keyword, Pageable pageable);
}
