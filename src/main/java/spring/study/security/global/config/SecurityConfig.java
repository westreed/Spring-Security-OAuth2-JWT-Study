package spring.study.security.global.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import spring.study.security.domain.repository.UserRepository;
import spring.study.security.global.jwt.filter.JwtAuthenticationProcessingFilter;
import spring.study.security.global.jwt.service.JwtService;
import spring.study.security.global.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import spring.study.security.global.login.handler.LoginFailureHandler;
import spring.study.security.global.login.handler.LoginSuccessHandler;
import spring.study.security.global.login.service.PrincipalDetailsService;
import spring.study.security.global.oauth2.handler.OAuth2LoginFailureHandler;
import spring.study.security.global.oauth2.handler.OAuth2LoginSuccessHandler;
import spring.study.security.global.oauth2.service.CustomOAuth2UserService;

@Configuration
@EnableWebSecurity // Spring Security Filter(SecurityConfig를 의미함)가 Spring Filter Chain에 등록됩니다.
@RequiredArgsConstructor
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PrincipalDetailsService principalDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
        http
            .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").authenticated()
                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
        );
        http.formLogin(AbstractHttpConfigurer::disable);
//        http.formLogin(form -> form
//                .loginPage("/loginForm")
//                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행합니다.
//                .defaultSuccessUrl("/")
//        );
        http.oauth2Login(oauth2 -> oauth2
                .loginPage("/loginForm")
                .successHandler(oAuth2LoginSuccessHandler)
                .failureHandler(oAuth2LoginFailureHandler)
                .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
//                .defaultSuccessUrl("/")
        );
        // 원래 스프링 시큐리티 필터 순서가 LogoutFilter 이후에 로그인 필터 동작
        // 따라서, LogoutFilter 이후에 우리가 만든 필터 동작하도록 설정
        // 그 이유는 JWT로 인증이 되었다면, Security 내부의 인가과정을 직접 처리하기 위해서임.
        // 순서 : LogoutFilter -> JwtAuthenticationProcessingFilter -> CustomJsonUsernamePasswordAuthenticationFilter
        http.addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationProcessingFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, userRepository);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }


    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(bCryptPasswordEncoder());
        provider.setUserDetailsService(principalDetailsService);
        return new ProviderManager(provider);
    }

    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {
        CustomJsonUsernamePasswordAuthenticationFilter authenticationFilter = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper);
        authenticationFilter.setAuthenticationManager(authenticationManager());
        authenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        authenticationFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return authenticationFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
        return new JwtAuthenticationProcessingFilter(jwtService, userRepository);
    }
}
