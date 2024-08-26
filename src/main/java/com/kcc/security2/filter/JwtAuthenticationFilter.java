package com.kcc.security2.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcc.security2.config.PrincilpalDetail;
import com.kcc.security2.config.PrincipalDetailService;
import com.kcc.security2.model.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
import java.util.Date;

// 로그인을 요청 했을때 실행된다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    //AuthenticationManager 은 정해진것이다.
    private final AuthenticationManager authenticationManager;

    //로그인 시도할때
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemtAuthentication 호출");

        //1. username , password 받기
        try{
            // User 객체 받아오기
            ObjectMapper om = new ObjectMapper();// json데이처를 파싱
            // request.getInputStream() 요청받은 아이디와 패스워드를 받아서 읽어서 user 객체에 넣어줌
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // UsernamePasswordAuthenticationToken에 sername과 password를 넣어줌
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 2. principalDetailService loadUserByUsername()호출
            // principalDetailService loadUserByUsername()을 호출해줘야함
            //authenticate(authenticationToken) : username을 전달
            // principal detail에 전달함 ,
            // return principalDetail 한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            //3. PrincilpalDetail 구한다.
            PrincilpalDetail principalDetail = (PrincilpalDetail) authentication.getPrincipal();
            System.out.println("principalDetail"+principalDetail);
            return  authentication;

        }catch(IOException e){
            e.printStackTrace();
        }


        return null;
    }

    // 로그인 성공했을때 작동함
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("로그인 성공");

        //JWT Token, 생성, 전송
        PrincilpalDetail principalDetail = (PrincilpalDetail) authResult.getPrincipal();
        System.out.println("successfulAuthentication"+principalDetail);
        String jwtToken = JWT.create()
                .withSubject("kosaToken")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))
                .withClaim("id",principalDetail.getUser().getId())
                .withClaim("username",principalDetail.getUser().getUsername())
                .sign(Algorithm.HMAC512("kcc"));
        response.addHeader("Authorization", "Bearer " + jwtToken);

    }
}
