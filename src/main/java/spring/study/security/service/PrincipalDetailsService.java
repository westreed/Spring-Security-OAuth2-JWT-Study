package spring.study.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.study.security.dto.auth.PrincipalDetails;
import spring.study.security.model.User;
import spring.study.security.repository.UserRepositroy;

// 시큐리티 설정에서 loginProcessingUrl("/login")에 의해 login 요청이 오면 자동으로 UserDetailsService 타입으로
// IoC 되어 있는 loadUserByUsername 함수가 실행됨!
@Service
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepositroy userRepositroy;

    public PrincipalDetailsService(UserRepositroy userRepositroy) {
        this.userRepositroy = userRepositroy;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepositroy.findByUsername(username);
        if (userEntity != null) {
            return new PrincipalDetails(userEntity);
        }
        throw new UsernameNotFoundException(username + " -> 없는 계정입니다.");
    }
}
