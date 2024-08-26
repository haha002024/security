package com.kcc.security2.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcc.security2.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.security.Principal;

// 로그인을 요청 했을때 실행된다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    //AuthenticationManager 은 정해진것이다.
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemtAuthentication 호출");

        //1. username , password 받기
        try{
            ObjectMapper om = new ObjectMapper();// json데이처를 파싱
            // request.getInputStream() 요청받은 아이디와 패스워드를 받아서 읽어서 user 객체에 넣어줌
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // username과 password를 넣어줌
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // principalDetailService loadUserByUsername()을 호출해줘야함
            //authenticate(authenticationToken) : username을 전달
            // principal detail에 전달함
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            Principal principal = (Principal) authentication.getPrincipal();
            return  authentication;

        }catch(IOException e){
            e.printStackTrace();
        }


        return null;
    }

}
