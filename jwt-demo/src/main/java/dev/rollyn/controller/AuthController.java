package dev.rollyn.controller;

import dev.rollyn.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class AuthController {

    private final TokenService tokenService;


    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public String token(Authentication authentication) {
        log.info("Generating token for {}",authentication.getName());
        return tokenService.generateToken(authentication);
    }
}
