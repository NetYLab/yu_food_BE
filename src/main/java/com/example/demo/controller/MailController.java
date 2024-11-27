//package com.example.demo.controller;
//
//import com.example.demo.service.MailService;
//import org.springframework.stereotype.Controller;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.ResponseBody;
//
//@Controller
//public class MailController {
//    private final MailService mailService;
//    private int number;
//
//    public MailController(MailService mailService) {
//        this.mailService = mailService;
//    }
//
//    // 인증 이메일 전송 코드
//    @ResponseBody
//    @PostMapping("/mail")
//    public String sendMail(String mail) {
//        number = mailService.sendMail(mail);
//        return "redirect:/check";
//    }
//}
