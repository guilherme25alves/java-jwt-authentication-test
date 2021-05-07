package com.avanade.dio.jwt.security;

import com.auth0.jwt.JWT;
import com.avanade.dio.jwt.data.UserData;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try{
            UserData credenciais = new ObjectMapper()
                    .readValue(request.getInputStream(), UserData.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            credenciais.getUsername(),
                            credenciais.getPassword(),
                            new ArrayList<>())
                    );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
        String token = JWT.create()
                .withSubject(((User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstraints.EXPIRATION_TIME))
                .sign(HMAC512(SecurityConstraints.SECRET.getBytes()));

        response.addHeader(SecurityConstraints.HEADER_STRING, SecurityConstraints.TOKEN_PREFIX + token);
    }

    // Método que gera o Token que valida o usuário de acesso ao sistema
}



/*
*  Classes Filter são interceptadores de requisições, tem por objetivo fazer o filtro,
*   por exemplo usuário válido ou não para permitir acesso na aplicação
*
* */