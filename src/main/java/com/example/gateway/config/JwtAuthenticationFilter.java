package com.example.gateway.config;

import com.example.gateway.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {


    @Autowired
    private final JWTUtil jwtUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthenticationFilter(JWTUtil jwtUtil){
        this.jwtUtil=jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        // Allow public OTP endpoints
        if (path.startsWith("/auth/send-otp") || path.startsWith("/auth/verify-otp")) {
            return chain.filter(exchange);
        }

        try {

            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return buildErrorResponse(exchange, "Missing or invalid Authorization header");
            }

            String token = authHeader.substring(7);

            jwtUtil.validateToken(token);

            return chain.filter(exchange);

        } catch (Exception e) {
            return buildErrorResponse(exchange, "Invalid or expired JWT token");
        }
    }
//build error response when the jwt token is invalid return 401 when there is any authentication issues
    private Mono<Void> buildErrorResponse(ServerWebExchange exchange, String message) {
        try {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());
            errorResponse.put("error", "Unauthorized");
            errorResponse.put("message", message);
            errorResponse.put("path", exchange.getRequest().getURI().getPath());

            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);

            return exchange.getResponse()
                    .writeWith(Mono.just(exchange.getResponse()
                            .bufferFactory()
                            .wrap(bytes)));

        } catch (Exception ex) {
            return exchange.getResponse().setComplete();
        }
    }


    //set the order of the current filter
    @Override
    public  int getOrder(){
        return -1;
    }
}
