package spring.study.security.global.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import spring.study.security.domain.repository.UserRepository;

import java.security.Key;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Service
public class JwtService implements InitializingBean {

    private final UserRepository userRepository;
    @Getter
    private final String BEARER = "Bearer ";
    private final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private final String NAME_CLAIM = "name";

    @Value("${jwt.secret}")
    private String secret;
    @Getter
    @Value("${jwt.access.header}")
    private String accessHeader;
    @Getter
    @Value("${jwt.refresh.header}")
    private String refreshHeader;
    // @Value("jwt.access.expiration")
    private final long accessTokenExpiration;
    // @Value("jwt.refresh.expiration")
    private final long refreshTokenExpiration;
    private Key key;

    public JwtService(
            UserRepository userRepository,
            @Value("${jwt.access.expiration}") long accessTokenExpiration,
            @Value("${jwt.refresh.expiration}") long refreshTokenExpiration
    ) {
        this.userRepository = userRepository;
        this.accessTokenExpiration = accessTokenExpiration * 1000;
        this.refreshTokenExpiration = refreshTokenExpiration * 1000;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(String username) {
        // 토큰의 expire 시간을 설정
        long now = (new Date()).getTime();
        Date validity = new Date(now + accessTokenExpiration);

        // JWT 용어가 헷갈릴 수 있는데, 내용 정리를 하자면
        // JWT는 Header, Payload, Signature로 이루어져 있음.
        // 의존성으로 추가한 JWT 라이브러리에서 Header는 알아서 생성해주고,
        // Payload와 Signature만 설정하면 된다.
        // 이때, Playload에 담겨 있는 데이터 조각들을 Claim이라고 부른다.
        // 이러한 Claim에서 이미 지정된 표현들이 있는데(Registered Claim),
        // iss (토큰발급자, issuer), sub (토큰제목, subject), aud (토큰대상자, audience)
        // exp (토큰만료시간, expiration), nbf (토큰활성날짜, not before), iat (토큰발급시간, issued at),
        // jti (토큰식별자, JWT ID)가 있다.
        // Jwts.builder()에서 이러한 예약데이터들은 메소드로 존재하고 그 외에 추가로 넣고 싶으면
        // claim 메소드를 통해 새롭게 추가할 수 있는 개념.
        return Jwts.builder()
                .setSubject(ACCESS_TOKEN_SUBJECT) // Jwt Subject
                .claim(NAME_CLAIM, username) // username 저장
                .setExpiration(validity) // set Expire Time 해당 옵션 안넣으면 expire안함
                .signWith(key, SignatureAlgorithm.HS512) // 사용할 암호화 알고리즘과 , signature 에 들어갈 secret값 세팅
                .compact();
    }

    /**
     * RefreshToken 생성
     * RefreshToken은 Claim에 email도 넣지 않으므로 withClaim() X
     */
    public String createRefreshToken() {
        long now = (new Date()).getTime();
        Date validity = new Date(now + refreshTokenExpiration);

        return Jwts.builder()
                .setSubject(REFRESH_TOKEN_SUBJECT)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(accessHeader, accessToken);
    }

    public void sendRefreshToken(HttpServletResponse response, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(refreshHeader, refreshToken);
    }

    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(accessHeader, accessToken);
        response.setHeader(refreshHeader, refreshToken);
    }

    public Optional<String> extractAccessToken(HttpServletRequest request) {
        log.info("extractAccessToken() 호출");
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(accessToken -> accessToken.startsWith(BEARER))
                .map(accessToken -> accessToken.replace(BEARER, ""));
    }

    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        log.info("extractRefreshToken() 호출");
        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Optional<String> extractUsername(String accessToken) {
        try {
            Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(accessToken)
                .getBody();
            log.info("extractUsername : {}", claims.get(NAME_CLAIM));
            return Optional.ofNullable((String) claims.get(NAME_CLAIM));
        } catch (Exception e) {
            log.error("액세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }

    public void setAccessTokenHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, accessToken);
    }

    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader, refreshToken);
    }

    public void updateRefreshToken(String username, String refreshToken) {
        userRepository.findByUsername(username).ifPresent(user -> user.updateRefreshToken(refreshToken));
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
            log.info("isTokenValid 호출 : {}", claims);
            return true;
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            return false;
        }
    }
}
