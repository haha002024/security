package com.kcc.security2.config;

import com.kcc.security2.model.User;
import com.kcc.security2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 로그인 후 호출되는 서비스 : UserDetailsService
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    // final변수를 초기화 하기 위해 : @RequiredArgsConstructor 사용
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("loadUserByUsername 호출....");
        User user = userRepository.findByUsername(username);

        return new PrincilpalDetail(user);
    }
}
