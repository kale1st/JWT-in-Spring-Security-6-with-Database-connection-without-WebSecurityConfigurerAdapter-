package com.kale.jwt_tutorial.dto;

import lombok.Data;

@Data
public class LoginDto {
    private String username;
    private String password;
}