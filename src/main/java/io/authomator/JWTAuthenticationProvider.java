package io.authomator;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class JWTAuthenticationProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		authentication.setAuthenticated(true);
		return authentication;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		if (authentication.equals(JWTAuthentication.class)) {
			return true;
		}
		return false;
	}

}
