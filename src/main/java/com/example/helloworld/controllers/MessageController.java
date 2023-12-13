package com.example.helloworld.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.helloworld.models.Message;
import com.example.helloworld.services.MessageService;

import lombok.RequiredArgsConstructor;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/messages")
public class MessageController {

    private final MessageService messageService;

    @GetMapping("/public")
    public Message getPublic() {
        return messageService.getPublicMessage();
    }

    @GetMapping("/protected")
    public Message getProtected() {
        return messageService.getProtectedMessage();
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('PRD:DELETE')")
    public Message getAdmin() {
        return messageService.getAdminMessage();
    }

    @GetMapping("/profile-jwt")
    public Map<String, Object> profileJwt(@AuthenticationPrincipal Jwt jwt) {
        return jwt.getClaims();
    }
}
