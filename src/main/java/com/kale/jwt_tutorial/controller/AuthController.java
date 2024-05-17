package com.kale.jwt_tutorial.controller;

import com.kale.jwt_tutorial.dao.AppUserRepository;
import com.kale.jwt_tutorial.dao.RoleRepository;
import com.kale.jwt_tutorial.dto.LoginDto;
import com.kale.jwt_tutorial.dto.RegisterDto;
import com.kale.jwt_tutorial.model.AppUser;
import com.kale.jwt_tutorial.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AppUserRepository appUserRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    @Autowired
    public AuthController(AppUserRepository appUserRepository,
                          RoleRepository roleRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.appUserRepository = appUserRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager=authenticationManager;
    }

    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto) {

        if (appUserRepository.existsByUsername(registerDto.getUsername())) {
            return new ResponseEntity<>("Username is taken!", HttpStatus.BAD_REQUEST);
        }

        AppUser appUser = new AppUser();
        appUser.setUsername(registerDto.getUsername());
        appUser.setPassword(passwordEncoder.encode((registerDto.getPassword())));

        Role roles = roleRepository.findByName(registerDto.getRole()).get();
        appUser.setRoles(Collections.singletonList(roles));

        appUserRepository.save(appUser);

        return new ResponseEntity<>("User registered success!", HttpStatus.OK);
    }

    @PostMapping("login")
    public ResponseEntity<String> login(@RequestBody LoginDto loginDto) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String response = "You have successfully logged in!";
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
