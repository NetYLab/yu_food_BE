package com.example.demo.service;

import com.example.demo.entity.Answer;
import com.example.demo.entity.Question;
import com.example.demo.entity.User;
import com.example.demo.repository.QuestionRepository;
import com.example.demo.repository.UserRepository;
import jakarta.persistence.criteria.*;
import jakarta.transaction.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class QuestionService {
    private final QuestionRepository questionRepository;
    private final UserRepository userRepository;
    public QuestionService(QuestionRepository questionRepository, UserRepository userRepository){
        this.questionRepository = questionRepository;
        this.userRepository = userRepository;
    }

    public Page<Question> getAllQuestions(int page, String keyword){
        List<Sort.Order> sortOrders = new ArrayList<>();
        sortOrders.add(Sort.Order.desc("createdAt"));
        Pageable pageable = PageRequest.of(page, 10, Sort.by(sortOrders));

        if(keyword == null || keyword.isEmpty())
            return questionRepository.findAll(pageable);
        else
            return questionRepository.findAllByKeyword(keyword, pageable);
    }

    public Page<Question> getAllQuestionsByAuthor(int page, User author){
        List<Sort.Order> sortOrders = new ArrayList<>();
        sortOrders.add(Sort.Order.desc("createdAt"));
        Pageable pageable = PageRequest.of(page, 10, Sort.by(sortOrders));
        return questionRepository.findByAuthor(author, pageable);
    }

    public Question getQuestionById(Long id){
        Optional<Question> question = questionRepository.findById(id);
        if(question.isPresent())
            return question.get();
        else
            throw new IllegalStateException("해당 질문이 없습니다.");
    }
    // 글 작성
    public void create(String title, String content, User user){
        Question question = new Question();
        question.setTitle(title);
        question.setContent(content);
        question.setAuthor(user);
        question.setCreatedAt(LocalDateTime.now());
        questionRepository.save(question);
    }
    // 글 수정
    public void edit(Question question, String newTitle, String newContent){
        question.setTitle(newTitle);
        question.setContent(newContent);
        question.setUpdatedAt(LocalDateTime.now());
        questionRepository.save(question);
    }
    // 글 삭제
    public void delete(Question question){
        questionRepository.delete(question);
    }

    // 글 검색
    private Specification<Question> search(String keyword){
        return new Specification<Question>() {
            private static final long serialVersionUID = 1L;
            @Override
            public Predicate toPredicate(Root<Question> q, CriteriaQuery<?> query, CriteriaBuilder cb) {
                query.distinct(true);
                Join<Question, User> author = q.join("author", JoinType.LEFT);
                Join<Question, Answer> answers = q.join("answers", JoinType.LEFT);
                Join<Answer, User> answerAuthor = answers.join("author", JoinType.LEFT);
                return cb.or(cb.like(q.get("title"), "%" + keyword + "%"), // 제목
                        cb.like(q.get("content"), "%" + keyword + "%"), // 내용
                        cb.like(author.get("username"), "%" + keyword + "%"), // 질문 작성자
                        cb.like(answers.get("content"), "%" + keyword + "%"), // 답변 내용
                        cb.like(answerAuthor.get("username"), "%" + keyword + "%")); // 답변 작성자
            }
        };
    }
}
