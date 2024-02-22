package spring.study.security.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import spring.study.security.model.User;
import spring.study.security.repository.UserRepositroy;

import java.util.List;
import java.util.Map;

// OAuth2 Client를 통해 로그인을 진행할 경우, 호출되는 서비스
// 라이브러리를 통해 인증 과정을 끝내고 AccessToken을 받은 시점에서 해당 서비스가 실행된다.
@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepositroy userRepositroy;

    public OAuth2UserService(UserRepositroy userRepositroy) {
        this.userRepositroy = userRepositroy;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Role generate
        List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

        // nameAttributeKey
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        // DB 저장로직이 필요하면 추가
        Map<String, Object> userAttributes = oAuth2User.getAttributes();
        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerId = userAttributes.get("sub").toString();
        String username = provider + "_" + providerId;
        System.out.println("username : " + username);
        User user = userRepositroy.findByUsername(username);
        if (user == null) {
            user = User.builder()
                    .username(username)
                    .email(userAttributes.get("email").toString())
                    .provider(provider)
                    .providerId(providerId)
                    .role("ROLE_USER")
                    .build();
            userRepositroy.save(user);
        }
        return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), userNameAttributeName);
    }
}
