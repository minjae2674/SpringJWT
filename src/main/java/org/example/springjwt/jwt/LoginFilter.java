package org.example.springjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springjwt.dto.CustomUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;

        //security filter chain에 등록했으나 custom filter를 쓰면서 여기에 집중 처리 가능
        //this.setFilterProcessesUrl("/api/v1/auth/login"); // 로그인 처리 URL 설정
        //this.setUsernameParameter("email"); // email을 username으로 사용
        //this.setPasswordParameter("password"); // password를 password로 사용
    }

    //json요청이 아니라 x-www-form-urlencoded방식은 아래 attemptAuthentication메서드 오버라이딩안해도 된다.

    //단, 부모의 attemptAuthentication()을 쓸 거면 super(authenticationManager)가 필요하고,
    //직접 오버라이딩해서 지금처럼 필드의 매니저를 쓸 거면 없어도 될 수 있지만 넣는 게 정석.
    @Override
    public Authentication attemptAuthentication (HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = obtainUsername(request); //request.getParameter랑 똑같음
        String password = obtainPassword(request); //로그인 할 때 클라이언트가 요청한 데이터 꺼내기.

        System.out.println(username + "로그인 시도");
        //UsernamePasswordAuthenticationFilter가 AuthenticationManager얘한테 로그인하라고 떠넘길 때
        //UsernamePasswordAuthenticationToken라는 dto에 요청값을 담아서 AuthenticationManager한테 전달해줘야함.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //매니저한테 토큰dto주고 너 로그인 검증 진행해봐 ~ / db -> detailservice
        return authenticationManager.authenticate(authToken);
        //-> 스프링시큐리티가 userdetailservice를 호출.
    }

    //return authenticationManager.authenticate(authToken); 바로 윗줄 코드에서
    //CustomUserDetailService로 갔다가,
    //인증성공하면 여기로 옴.
    //authentication객체에 customdetails가 있음
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication){
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        //role값 뽑기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        //jwt생성
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        //만든 jwt토큰을 브라우저로 보냄.
        response.addHeader("Authorization", "Bearer " + token);

    }

    //실패하면
    @Override
    protected  void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,AuthenticationException failed) {

        response.setStatus(401);
    }

}
