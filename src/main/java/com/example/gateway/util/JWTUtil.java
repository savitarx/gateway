package com.example.gateway.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JWTUtil {



    //get the token from resources folder and set the secret value in the secret variable
    @Value("${jwt.secret}")
    private String secret;

    //Accepts token as a parameter and returns the claims to the calling function
    public Claims  validateToken(String token) {
        return Jwts.parserBuilder().
                setSigningKey(secret.getBytes())
                .build().parseClaimsJws(token)
                .getBody();
    }
}
