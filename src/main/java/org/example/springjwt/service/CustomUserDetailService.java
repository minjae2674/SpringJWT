package org.example.springjwt.service;

import org.example.springjwt.dto.CustomUserDetails;
import org.example.springjwt.entity.UserEntity;
import org.example.springjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //Db에서 로그인한 사람 정보 username으로 찾아서 가져옴
        UserEntity userData = userRepository.findByUsername(username);

        if (userData != null) {
            return new CustomUserDetails(userData);
            // DB에서 찾은 UserEntity를 Spring Security가 이해할 수 있는 UserDetails 형태로 감싼다.

            // 여기서는 비밀번호 검증을 직접 하지 않는다.

            // 반환된 CustomUserDetails는 AuthenticationProvider로 넘어가고,

            // AuthenticationProvider가 getPassword()로 DB 비밀번호 해시를 꺼내

            // 사용자가 입력한 비밀번호와 PasswordEncoder.matches()로 비교한다.

            // 검증 성공 시 인증 완료된 Authentication 객체의 principal에 CustomUserDetails가 담기고,

            // 이후 LoginFilter의 successfulAuthentication()이 호출된다.
        }

        return null;
    }
}
