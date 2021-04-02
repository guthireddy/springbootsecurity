package com.security.springsecurityboot.config;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.util.CollectionUtils;

public class AudienceValidator implements OAuth2TokenValidator<Jwt> {
	private static final BearerTokenError MISSING_AUDIENCE = new BearerTokenError("invalid_token",
			HttpStatus.UNAUTHORIZED, "The Token is missing a requiered Audience", null);

	public OAuth2TokenValidatorResult validate(Jwt token) {
		List<String> audience = token.getAudience();
		if (!CollectionUtils.isEmpty(audience)) {
			return OAuth2TokenValidatorResult.success();
		} else {
			return OAuth2TokenValidatorResult.failure(MISSING_AUDIENCE);
		}
	}
}
