# Spring Security OAuth2 Study

출처
1. 인프런의 [스프링부트 시큐리티 & JWT 강의](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0)
2. [sh111-coder님의 oauth2WithJwtLogin 레포](https://github.com/sh111-coder/oauth2WithJwtLogin)

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
3. 사용자의 권한(Role)을 확인하고 접근을 허용함. (Authorization)

# 테스트 방법

## 일반로그인
1. `POST http://localhost:8080/join` 으로 ID/PW/Email을 입력해서 가입.
2. `http://localhost:8080/loginForm` 접속.
3. 로그인 페이지에서 로그인 진행.
4. Console Log 확인.

## OAuth2 로그인
1. `http://localhost:8080/loginForm` 접속.
2. 구글 로그인 진행.
3. Network에서 응답헤더에 JWT 있는지 확인.

