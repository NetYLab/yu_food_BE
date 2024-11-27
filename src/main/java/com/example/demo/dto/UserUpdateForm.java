package com.example.demo.dto;

import jakarta.validation.constraints.NotEmpty;

public class UserUpdateForm {
    @NotEmpty(message = "기존 비밀번호를 입력해주세요.")
    private String OriginalPassword;

    @NotEmpty(message = "새 비밀번호를 입력해주세요.")
    private String NewPassword;

    @NotEmpty(message = "새 비밀번호를 확인해주세요.")
    private String NewPasswordCheck;

    // Getter and Setter for OriginalPassword
    public String getOriginalPassword() {
        return OriginalPassword;
    }

    public void setOriginalPassword(String originalPassword) {
        OriginalPassword = originalPassword;
    }

    // Getter and Setter for NewPassword
    public String getNewPassword() {
        return NewPassword;
    }

    public void setNewPassword(String newPassword) {
        NewPassword = newPassword;
    }

    // Getter and Setter for NewPasswordCheck
    public String getNewPasswordCheck() {
        return NewPasswordCheck;
    }

    public void setNewPasswordCheck(String newPasswordCheck) {
        NewPasswordCheck = newPasswordCheck;
    }
}
