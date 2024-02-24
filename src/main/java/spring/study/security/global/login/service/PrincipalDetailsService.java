package spring.study.security.global.login.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.study.security.global.login.dto.PrincipalDetails;
import spring.study.security.domain.model.User;
import spring.study.security.domain.repository.UserRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

// 시큐리티 설정에서 loginProcessingUrl("/login")에 의해 login 요청이 오면 자동으로 UserDetailsService 타입으로
// IoC 되어 있는 loadUserByUsername 함수가 실행됨!
@Slf4j
@Service
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public PrincipalDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("PrincipalDetailsService의 loadUserByUsername({}) 호출됨", username);
        Optional<User> userEntity = userRepository.findByUsername(username);
        if (userEntity.isPresent()) {
            return new PrincipalDetails(userEntity.get());
        }
        throw new UsernameNotFoundException(username + " -> 없는 계정입니다.");
    }

    private org.springframework.security.core.userdetails.User createUser(String username, User user) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add((GrantedAuthority) user::getRole);

        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(),
                grantedAuthorities);
    }
}
