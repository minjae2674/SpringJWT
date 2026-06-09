package org.example.springjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springjwt.dto.CustomUserDetails;
import org.example.springjwt.entity.UserEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //request에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");

        //Authorization 헤더 검증. 아직 로그인 안한상태. jwt발급 전
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("JWTFilter 클래스 : 로그인 전이라 토큰발급전. token null");
            filterChain.doFilter(request, response);

            //조건이 해당되면 다음 체인을 동작시키고 메소드 종료
            return;
        }

        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        //토큰이 소멸되었다면
        if (jwtUtil.isExpired(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        //토큰이 정상적이라면 즉, 정상로그인 사용자라면
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 세팅
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        //로그인한 상태이고, role이 뭔지가 중요한거지 비밀번호는 이미 로그인 검증 끝났기때문에
        //contextholder에 넣는게 중요하기에 아무거나 해도 상관없음
        userEntity.setPassword("아무거나지정");
        userEntity.setRole(role);

        //UserDetails에 회원정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        //왜 credentials가 null이냐면, 인증이 끝난 뒤에는 비밀번호 같은 민감정보를 계속 들고 있을 필요가 없기 때문
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        //이제 세션에 로그인사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request,response);


    }
}
