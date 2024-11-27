package com.example.demo.dto;

import jakarta.validation.constraints.NotEmpty;

public class AnswerForm {
    @NotEmpty(message = "내용을 입력해주세요.")
    private String content;

    // Getter
    public String getContent() {
        return content;
    }

    // Setter
    public void setContent(String content) {
        this.content = content;
    }
}
