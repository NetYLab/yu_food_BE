package com.example.demo.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public class QuestionForm {
    @NotEmpty(message = "제목을 입력해주세요.")
    @Size(max = 255)
    private String title;

    @NotEmpty(message = "내용을 입력해주세요.")
    private String content;

    // Getter and Setter for title
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    // Getter and Setter for content
    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}
