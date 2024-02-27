package spring.study.security.global.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;
import spring.study.security.domain.model.User;
import spring.study.security.domain.repository.UserRepository;
import spring.study.security.global.jwt.service.JwtService;

import java.io.IOException;

@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private static final String NO_CHECK_URL = "/login";

    public JwtAuthenticationProcessingFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JwtAuthenticationProcessingFilter() 호출 : {}", request.getRequestURI());
        if (request.getRequestURI().equals(NO_CHECK_URL)){
            log.info("URL PASS");
            filterChain.doFilter(request, response);
            return;
        }

        // 요청헤더에서 RefreshToken을 추출합니다.
        String refreshToken = jwtService.extractRefreshToken(request)
                .filter(jwtService::isTokenValid)
                .orElse(null);

        // RefreshToken이 존재하는 경우,토큰이 만료되어 재갱신 요청임.
        if (refreshToken != null) {
            checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            return;
        }

        checkAccessTokenAndAuthentication(request, response, filterChain);
    }

    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
        userRepository.findByRefreshToken(refreshToken)
                .ifPresent(
                        user -> {
                            String reIssueRefreshToken = reIssueRefreshToken(user);
                            jwtService.sendAccessAndRefreshToken(
                                    response,
                                    jwtService.createAccessToken(user.getUsername()),
                                    reIssueRefreshToken
                            );
                        });
    }

    private String reIssueRefreshToken(User user) {
        String reIssuedRefreshToken = jwtService.createRefreshToken();
        user.updateRefreshToken(reIssuedRefreshToken);
        userRepository.saveAndFlush(user);
        return reIssuedRefreshToken;
    }

    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("checkAccessTokenAndAuthentication() 호출");
        jwtService
                .extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(accessToken -> jwtService.extractUsername(accessToken)
                        .ifPresent(username -> userRepository.findByUsername(username)
                                .ifPresent(this::saveAuthentication)));

        filterChain.doFilter(request, response);
    }

    public void saveAuthentication(User user) {
        log.info("saveAuthentication() 호출 : {}", user);
        UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password("")
            .roles(user.getRole().replace("ROLE_", ""))
            .build();

        // UsernamePasswordAuthenticationToken 객체를 생성할 때
        // User의 Authorities를 함께 제공하면, 인증된 사용자 객체로 생성된다.
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            userDetailsUser,
            null,
            userDetailsUser.getAuthorities()
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
