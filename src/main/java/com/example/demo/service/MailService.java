//package com.example.demo.service;
//
//import jakarta.mail.MessagingException;
//import jakarta.mail.internet.MimeMessage;
//import org.springframework.mail.javamail.JavaMailSender;
//import org.springframework.scheduling.annotation.Async;
//import org.springframework.stereotype.Service;
//
//@Service
//public class MailService {
//    private final JavaMailSender javaMailSender;
//    private static final String senderEmail = "cadam9601028@gmail.com";
//    private static int number;
//
//    public MailService(JavaMailSender javaMailSender) {
//        this.javaMailSender = javaMailSender;
//    }
//
//    // 이메일 인증번호(랜덤으로 숫자 생성)
//    public static void setNumber() {
//        number = (int) (Math.random() * (90000)) + 100000;
//    }
//
//    @Async
//    public MimeMessage createMail(String mail) {
//        setNumber();
//        MimeMessage message = javaMailSender.createMimeMessage();
//
//        try {
//            message.setFrom(senderEmail);
//            message.setRecipients(MimeMessage.RecipientType.TO, mail);
//            message.setSubject("계정 인증 이메일");
//            String body = "";
//            body += "<h3>" + "요청하신 인증번호입니다." + "</h3>";
//            body += "<h1>" + number + "</h1>";
//            body += "<h3>" + "감사합니다." + "</h3>";
//            message.setText(body, "UTF-8", "html");
//        } catch (MessagingException e) {
//            e.printStackTrace();
//        }
//        return message;
//    }
//
//    public int sendMail(String mail){
//        MimeMessage message = createMail(mail);
//        javaMailSender.send(message);
//
//        return number;
//    }
//}
