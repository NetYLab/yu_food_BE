package com.example.demo.controller;

import com.example.demo.dto.UserUpdateForm;
import com.example.demo.entity.Answer;
import com.example.demo.entity.Question;
import com.example.demo.entity.User;
import com.example.demo.service.AnswerService;
import com.example.demo.service.JoinService;
import com.example.demo.service.MyService;
import com.example.demo.service.QuestionService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
@RequestMapping("/user")
public class MyController {
    private final MyService myService;
    private final QuestionService questionService;
    private final AnswerService answerService;

    public MyController(MyService myService, QuestionService questionService, AnswerService answerService){
        this.myService = myService;
        this.questionService = questionService;
        this.answerService = answerService;
    }
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/my")
    public String my(UserUpdateForm form, @RequestParam(value="question-page", defaultValue="0") int questionPage,
                     @RequestParam(value="answer-page", defaultValue="0") int answerPage,
                     Principal principal, Model model){
        User user = myService.getUserByUsername(principal.getName());
        Page<Question> wroteQuestions = questionService.getAllQuestionsByAuthor(questionPage, user);
        Page<Answer> wroteAnswers = answerService.getAllAnswersByAuthor(answerPage, user);

        model.addAttribute("wroteQuestions", wroteQuestions);
        model.addAttribute("wroteAnswers", wroteAnswers);
        model.addAttribute("username", user.getUsername());
        model.addAttribute("email", user.getEmail());
        return "my";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/my/update")
    public String update(@Valid UserUpdateForm form, BindingResult bindingResult, Principal principal,
                         Model model){
        User user = myService.getUserByUsername(principal.getName());
        Page<Question> wroteQuestions = questionService.getAllQuestionsByAuthor(0, user);
        Page<Answer> wroteAnswers = answerService.getAllAnswersByAuthor(0, user);

        model.addAttribute("wroteQuestions", wroteQuestions);
        model.addAttribute("wroteAnswers", wroteAnswers);
        model.addAttribute("username", user.getUsername());
        model.addAttribute("email", user.getEmail());

        if(bindingResult.hasErrors()){
            return "my";
        }

        if(!myService.isMatch(form.getOriginalPassword(), user.getPassword())){
            bindingResult.rejectValue("originalPassword", "passwordInCorrect", "기존 비밀번호가 일치하지 않습니다.");
            return "my";
        }
        if(!form.getNewPassword().equals(form.getNewPasswordCheck())){
            bindingResult.rejectValue("newPasswordCheck", "passwordInCorrect", "확인 비밀번호가 일치하지 않습니다.");
            return "my";
        }
        try{
            myService.update(user, form.getNewPassword());
        } catch (Exception e){
            e.printStackTrace();
            bindingResult.reject("updateError", e.getMessage());
        }
        return "redirect:/user/my";
    }

    @GetMapping("/find-email")
    public String findEmail(){
        return "find_email";
    }

    @PostMapping("/find-email")
    public String findEmail(@RequestParam String name, Model model){
        String email = myService.findEmailByName(name).orElse(null);
        if(email != null){
            model.addAttribute("foundEmail", email);
            return "found_email";
        } else {
            model.addAttribute("notFound", "해당 이름에 대한 이메일을 찾을 수 없습니다.");
            return "find_email";
        }
    }
}
