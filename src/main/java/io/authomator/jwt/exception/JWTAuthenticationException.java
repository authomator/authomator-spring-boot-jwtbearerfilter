package io.authomator.jwt.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;


@ResponseStatus(value=HttpStatus.FORBIDDEN)
public class JWTAuthenticationException extends AuthenticationException {

	private static final long serialVersionUID = -551156175648379326L;
		
	public JWTAuthenticationException() {
		super("Invalid JWT token");
	}
	
	public JWTAuthenticationException(String message) {
		super(message);
	}
		
}
