package com.example.demo.service;

import com.example.demo.entity.Answer;
import com.example.demo.entity.Question;
import com.example.demo.entity.User;
import com.example.demo.repository.AnswerRepository;
import com.example.demo.repository.QuestionRepository;
import jakarta.transaction.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class AnswerService {
    private final AnswerRepository answerRepository;
    private final QuestionRepository questionRepository;

    public AnswerService(AnswerRepository answerRepository, QuestionRepository questionRepository){
        this.answerRepository = answerRepository;
        this.questionRepository = questionRepository;
    }

    public Page<Answer> getAllAnswers(Question question, int page){
        List<Sort.Order> sortOrders = new ArrayList<>();
        sortOrders.add(Sort.Order.desc("createdAt"));
        Pageable pageable = PageRequest.of(page, 5, Sort.by(sortOrders));
        return answerRepository.findByQuestionId(question, pageable);
    }

    public Page<Answer> getAllAnswersByAuthor(int page, User author){
        List<Sort.Order> sortOrders = new ArrayList<>();
        sortOrders.add(Sort.Order.desc("createdAt"));
        Pageable pageable = PageRequest.of(page, 5, Sort.by(sortOrders));
        return answerRepository.findByAuthor(author, pageable);
    }

    // 댓글 작성
    public Answer add(Question question, String content, User author){
        // 댓글을 작성할 질문을 찾는다.
//        Question question = questionRepository.findById(questionId)
//                .orElseThrow(() -> new IllegalArgumentException("해당 질문이 없습니다."));
        Answer answer = new Answer();
        answer.setQuestion(question);
        answer.setContent(content);
        answer.setAuthor(author);
        answer.setCreatedAt(LocalDateTime.now());
        answerRepository.save(answer);
        return answer;
    }
    // 댓글 조회
    public Answer getAnswer(Long id){
        Optional<Answer> answer = answerRepository.findById(id);
        if(answer.isPresent())
            return answer.get();
        else
            throw new IllegalStateException("해당 댓글이 없습니다.");
    }

    // 댓글 수정
    public void edit(Answer answer, String newContent) {
        answer.setContent(newContent);
        answer.setCreatedAt(LocalDateTime.now());
        answerRepository.save(answer);
    }
    // 댓글 삭제
    public void delete(Answer answer){
        answerRepository.delete(answer);
    }
}
