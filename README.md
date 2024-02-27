# Spring Security OAuth2 Study

출처 : 인프런의 [스프링부트 시큐리티 & JWT 강의](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0)

# Flow 설명

## 일반 로그인

1. 사용자가 `POST /login`으로 ID/PW를 통한 로그인을 진행함.
2. CustomJsonUsernamePasswordAuthenticationFilter를 통해 인증/인가 처리.
3. LoginSuccessHandler를 통해, JWT 토큰 생성 후 Response.

## OAuth2 로그인

1. 사용자가 `POST /login/oauth2/code/<provider>`으로 OAuth2 로그인을 진행함.
2. Spring OAuth2 Client 라이브러리에 의해, CustomOAuth2UserService에서 인증/인가 처리.
3. OAuth2LoginSuccessHandler를 통해, JWT 토큰 생성 후 Response.

## 발급 받은 JWT를 통한 인가 처리

1. 사용자의 요청 Header에 `Authorization Bearer <JWT>`이 포함됨.
2. 이를 JwtAuthenticationProcessingFilter를 통해, JWT를 검증하고 Payload로부터 사용자정보를 얻음.
3. 사용자의 권한(Role)을 확인하고 접근을 허용함.