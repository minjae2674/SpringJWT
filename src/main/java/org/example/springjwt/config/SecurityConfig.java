package org.example.springjwt.config;

import org.example.springjwt.jwt.JWTFilter;
import org.example.springjwt.jwt.JWTUtil;
import org.example.springjwt.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    private final AuthenticationConfiguration authenticationConfiguration;

//    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration) {
//        this.authenticationConfiguration = authenticationConfiguration;
//    }
    //@Bean 메서드가 반환하는 객체는 기본적으로 메서드명을 Bean 이름으로 등록. 따라서 없어도 되는 코드.
    //@Configuration 클래스도 Spring Bean으로 등록되므로 생성자 주입이 가능하다.

    //component로 jwtutil이 등록되었기 때문에 filterchain메서드에 바로 주입도 가능. 아래 주석풀고 사용도 가능.
//    private final JWTUtil jwtUtil;
//
//    public SecurityConfig(JWTUtil jwtUtil) {
//        this.jwtUtil = jwtUtil;
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
        //@Configuration 클래스도 Spring Bean으로 등록되므로 생성자 주입이 가능하다.
        //@Bean 메서드가 반환하는 객체는 기본적으로 메서드명을 Bean 이름으로 등록.
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager, JWTUtil jWTUtil, JWTFilter jWTFilter) throws Exception {

        //csrf disable
        http.csrf(auth -> auth.disable());

        //form 로그인 방식 disable
        http.formLogin(auth -> auth.disable());
        //http basic 인증방식 disable
        http.httpBasic(auth -> auth.disable());
        //경로별 인가작업
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/", "/join").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
        );

        //authenticationManager, jwtutil을 멤버변수, 생성자로 등록 안하고 filterchain파라미터로 빈 주입
        http.addFilterAt(new LoginFilter(authenticationManager, jWTUtil), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jWTFilter,LoginFilter.class);

        //세션 설정
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }
}
