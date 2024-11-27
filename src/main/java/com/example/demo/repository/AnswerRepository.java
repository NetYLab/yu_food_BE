package com.example.demo.repository;

import com.example.demo.entity.Answer;
import com.example.demo.entity.Question;
import com.example.demo.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AnswerRepository extends JpaRepository<Answer, Long>{
    Page<Answer> findByQuestionId(Question question, Pageable pageable);
    Page<Answer> findByAuthor(User author, Pageable pageable);
}
