package com.kcc.security2.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.kcc.security2.config.PrincilpalDetail;
import com.kcc.security2.model.User;
import com.kcc.security2.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// 로그인한 유저의 권한이 있는지 없는지에 대해 필터링
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository){
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //super.doFilterInternal(request, response, chain);
        System.out.println("jwt 필터 호출");

        // 1.filter를 받아내서 찍어보고
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtToken: " + jwtHeader);

        //JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }

        // 실제 토근
        String jwtToken = request.getHeader("Authorization")
                .replace("Bearer ", "");
        // verify(토큰값) 토큰 값을 복호화한다.
        String username = JWT.require(Algorithm.HMAC512("kcc"))
                .build().verify(jwtToken).getClaim("username").asString();
        System.out.println("username: " + username);

        if(username != null){
            User userEntity = userRepository.findByUsername(username);
            PrincilpalDetail princilpalDetail = new PrincilpalDetail(userEntity);
            Authentication authentication = new UsernamePasswordAuthenticationToken(princilpalDetail, null,
                    princilpalDetail.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
