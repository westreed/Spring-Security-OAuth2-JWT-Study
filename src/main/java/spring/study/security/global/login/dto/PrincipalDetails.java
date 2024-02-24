package spring.study.security.global.login.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import spring.study.security.domain.model.User;

import java.util.*;

// 시큐리티가 /login주소 요청이 오면 낚아채서 로그인을 진행시킴.
// 로그인 진행이 완료가 되면, 시큐리티 session(일반적인 세션 X)을 만들어줍니다. (key: Security ContextHolder)
// 세션에 들어갈 수 있는 오브젝트는 정해져 있음. => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 됨.
// User 오브젝트 타입 => UserDetails 타입 객체

// Security Session => Authentication => UserDetails

public class PrincipalDetails extends DefaultOAuth2User implements UserDetails {

    private final User user;

    public PrincipalDetails(User user) {
        super(null, new HashMap<>(){{put("id", null);}}, "id");
        this.user = user;
    }

    public PrincipalDetails(User user, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes, String nameAttributeKey) {
        super(authorities, attributes, nameAttributeKey);
        this.user = user;
    }

    // 해당 User의 권한을 리턴하는 곳!
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add((GrantedAuthority) user::getRole);
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        // 우리사이트에서 1년 동안 회원이 로그인을 안하면 휴면 계정으로 전환하기로 결정했음.
        // 로그인 날짜를 가져와서 1년이 지났으면 return false; 하는 식

        return true;
    }
}
