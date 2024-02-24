package spring.study.security.global.oauth2.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import spring.study.security.domain.repository.UserRepository;
import spring.study.security.global.jwt.service.JwtService;
import spring.study.security.global.login.dto.PrincipalDetails;
import spring.study.security.global.oauth2.CustomOAuth2User;

import java.io.IOException;

@Slf4j
@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    public OAuth2LoginSuccessHandler(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");
        try {
            PrincipalDetails oAuth2User = (PrincipalDetails) authentication.getPrincipal();
            loginSuccess(response, oAuth2User); // 로그인에 성공한 경우 access, refresh 토큰 생성
        } catch (Exception e) {
            throw e;
        }

    }

    // TODO : 소셜 로그인 시에도 무조건 토큰 생성하지 말고 JWT 인증 필터처럼 RefreshToken 유/무에 따라 다르게 처리해보기
    private void loginSuccess(HttpServletResponse response, PrincipalDetails oAuth2User) throws IOException {
        String accessToken = jwtService.createAccessToken(oAuth2User.getUsername());
        String refreshToken = jwtService.createRefreshToken();
        response.addHeader(jwtService.getAccessHeader(), jwtService.getBEARER() + accessToken);
        response.addHeader(jwtService.getRefreshHeader(), jwtService.getBEARER() + refreshToken);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        userRepository.findByUsername(oAuth2User.getUsername())
                .ifPresent(user -> {
                    user.updateRefreshToken(refreshToken);
                    userRepository.saveAndFlush(user);
                });
        response.sendRedirect("/");
    }
}
