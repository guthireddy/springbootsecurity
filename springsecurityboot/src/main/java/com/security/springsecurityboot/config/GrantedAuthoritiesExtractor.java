package com.security.springsecurityboot.config;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

public class GrantedAuthoritiesExtractor extends JwtAuthenticationConverter{
	
	@Override
	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt){
		Collection<String> scopes = (Collection<String>)jwt.getClaims().get("scope");
		return scopes.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

}
