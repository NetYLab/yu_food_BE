package com.example.demo.controller;

import com.example.demo.dto.AnswerForm;
import com.example.demo.entity.Answer;
import com.example.demo.entity.Question;
import com.example.demo.entity.User;
import com.example.demo.service.AnswerService;
import com.example.demo.service.JoinService;
import com.example.demo.service.QuestionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;

@RequestMapping("/answer")
@Controller
public class AnswerController {
    private final QuestionService questionService;
    private final AnswerService answerService;
    private final JoinService joinService;
    public AnswerController(QuestionService questionService, AnswerService answerService, JoinService joinService){
        this.questionService = questionService;
        this.answerService = answerService;
        this.joinService = joinService;
    }

    // 답변 작성
    @PostMapping("/new/{id}")
    @PreAuthorize("isAuthenticated()")
    public String addAnswer(Model model, @PathVariable("id") Long id,
                            @Valid AnswerForm answerForm, BindingResult bindingResult, Principal principal){
        Question question = questionService.getQuestionById(id);
        User user = joinService.getUser(principal.getName());
        if(bindingResult.hasErrors()){
            model.addAttribute("question", question);
            return "question_detail";
        }
        Answer answer = answerService.add(question, answerForm.getContent(), user);
        return String.format("redirect:/question/detail/%s#answer_%s", answer.getQuestion().getId(), answer.getId());
    }

    // 답변 수정
    @GetMapping("/edit/{id}")
    @PreAuthorize("isAuthenticated()")
    public String editAnswer(AnswerForm answerForm, @PathVariable("id") Long id, Principal principal){
        Answer answer = answerService.getAnswer(id);
        if(!answer.getAuthor().getUsername().equals(principal.getName()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "작성자만 수정할 수 있습니다.");
        answerForm.setContent(answer.getContent());
        return "answer_form";
    }

    @PostMapping("/edit/{id}")
    @PreAuthorize("isAuthenticated()")
    public String editAnswer(@Valid AnswerForm answerForm, BindingResult bindingResult,
                             @PathVariable("id") Long id, Principal principal){
        if(bindingResult.hasErrors())
            return "answer_form";
        Answer answer = answerService.getAnswer(id);
        if(!answer.getAuthor().getUsername().equals(principal.getName()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "작성자만 수정할 수 있습니다.");
        answerService.edit(answer, answerForm.getContent());
        return String.format("redirect:/question/detail/%s#answer_%s", answer.getQuestion().getId(), answer.getId());
    }

    // 답변 삭제
    @GetMapping("/delete/{id}")
    @PreAuthorize("isAuthenticated()")
    public String deleteAnswer(Principal principal, @PathVariable("id") Long id){
        Answer answer = answerService.getAnswer(id);
        if(!answer.getAuthor().getUsername().equals(principal.getName()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "작성자만 삭제할 수 있습니다.");
        answerService.delete(answer);
        return String.format("redirect:/question/detail/%s", answer.getQuestion().getId());
    }
}
