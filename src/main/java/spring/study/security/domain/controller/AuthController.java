package spring.study.security.domain.controller;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import spring.study.security.domain.dto.UserDto;
import spring.study.security.domain.model.User;
import spring.study.security.domain.repository.UserRepository;

import java.util.Optional;

@Slf4j
@AllArgsConstructor
@RestController
public class AuthController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/join")
    public @ResponseBody String join(@Valid @RequestBody UserDto userDto) throws BadRequestException {
        log.info("POST /join UserDto : {}", userDto);

        Optional<User> userEntity = userRepository.findByUsername(userDto.getUsername());
        if (userEntity.isPresent()) {
            throw new BadRequestException("이미 가입된 유저입니다.");
        }

        User user = User.builder()
                .username(userDto.getUsername())
                .password(userDto.getPassword())
                .email(userDto.getEmail())
                .build();
        user.authorizeUser();
        user.passwordEncode(bCryptPasswordEncoder);
        userRepository.save(user);
        return "redirect:/loginForm";
    }
}
