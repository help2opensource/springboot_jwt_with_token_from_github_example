package com.example.githubjwt.util;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtTokenProvider {

    @Value("${secret-key}")
    private String SECRET_KEY;
    
    private final long EXPIRATION_TIME = 86400000; // 24 hours

    public String createToken(OAuth2User user) {
        return Jwts.builder()
                .setSubject(user.getAttribute("login"))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Extract the token from the Authorization header
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Extract the token
        }
        return null;
    }

    // Extract the Authentication object based on the JWT
    public Authentication getAuthentication(String token) {

        // Parse the JWT to get the username (subject)
        Claims claims = getClaims(token);
        String username = claims.getSubject();

        // Create the Authentication object (UserDetails could be extended as needed)
        return new UsernamePasswordAuthenticationToken(username, token, null);
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }
}