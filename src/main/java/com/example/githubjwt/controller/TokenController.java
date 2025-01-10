package com.example.githubjwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.githubjwt.util.JwtTokenProvider;

@RestController
@RequestMapping("/api")
public class TokenController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @GetMapping("/token")
    public String generateToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        return jwtTokenProvider.createToken(oauthUser);
    }

}
