package com.example.demo.controller;

import com.example.demo.dto.AnswerForm;
import com.example.demo.dto.QuestionForm;
import com.example.demo.entity.Answer;
import com.example.demo.entity.Question;
import com.example.demo.entity.User;
import com.example.demo.repository.QuestionRepository;
import com.example.demo.service.AnswerService;
import com.example.demo.service.JoinService;
import com.example.demo.service.QuestionService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;

@RequestMapping("/question")
@Controller
public class QuestionController {
    private final QuestionService questionService;
    private final AnswerService answerService;
    private final JoinService joinService;

    public QuestionController(QuestionService questionService, JoinService joinService, AnswerService answerService) {
        this.questionService = questionService;
        this.joinService = joinService;
        this.answerService = answerService;
    }

    @GetMapping("/list")
    public String QuestionList(Model model, @RequestParam(value="page", defaultValue="0") int page, @RequestParam(value="keyword", defaultValue="") String keyword){
        Page<Question> paging = questionService.getAllQuestions(page, keyword);
        model.addAttribute("paging", paging);
        model.addAttribute("keyword", keyword);
        return "question_list";
    }

    @GetMapping(value ="/detail/{id}")
    public String QuestionDetail(Model model, @PathVariable("id") Long id, AnswerForm answerForm,
                                 @RequestParam(value="ans-page", defaultValue="0") int answerPage) {
        Question question = questionService.getQuestionById(id);
        Page<Answer> answerPaging = answerService.getAllAnswers(question, answerPage);
        model.addAttribute("question", question);
        model.addAttribute("answerPaging", answerPaging);
        return "question_detail";
    }

    @GetMapping("/new")
    @PreAuthorize("isAuthenticated()")
    public String createQuestion(QuestionForm questionForm) {
        return "question_form";
    }

    @PostMapping("/new")
    @PreAuthorize("isAuthenticated()")
    public String createQuestion(@Valid QuestionForm questionForm, BindingResult bindingResult, Principal principal) {
        if (bindingResult.hasErrors())
            return "question_form";
        User user = joinService.getUser(principal.getName());
        questionService.create(questionForm.getTitle(), questionForm.getContent(), user);
        return "redirect:/question/list";
    }

    @GetMapping("/edit/{id}")
    @PreAuthorize("isAuthenticated()")
    public String editQuestion(QuestionForm questionForm, @PathVariable("id") Long id, Principal principal) {
        Question question = questionService.getQuestionById(id);
        if (!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"본인이 작성한 글만 수정할 수 있습니다.");
        }
        questionForm.setTitle(question.getTitle());
        questionForm.setContent(question.getContent());
        return "question_form";
    }

    @PostMapping("/edit/{id}")
    @PreAuthorize("isAuthenticated()")
    public String editQuestion(@Valid QuestionForm questionForm, BindingResult bindingResult,
                               Principal principal, @PathVariable("id") Long id) {
        if (bindingResult.hasErrors())
            return "question_form";
        Question question = questionService.getQuestionById(id);
        if (!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new SecurityException("본인이 작성한 글만 수정할 수 있습니다.");
        }
        questionService.edit(question, questionForm.getTitle(), questionForm.getContent());
        return String.format("redirect:/question/detail/%s", id);
    }

    @GetMapping("/delete/{id}")
    @PreAuthorize("isAuthenticated()")
    public String deleteQuestion(@PathVariable Long id, Principal principal) {
        Question question = questionService.getQuestionById(id);
        if (!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"본인이 작성한 글만 삭제할 수 있습니다.");
        }
        questionService.delete(question);
        return "redirect:/question_list";
    }
}
