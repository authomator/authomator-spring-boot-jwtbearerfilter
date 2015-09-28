package io.authomator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class JWTAuthentication implements Authentication{

	private static final long serialVersionUID = 1L;

	private JwtClaims jwtClaims;
	private boolean authenticated = false;
	
	
	JWTAuthentication(JwtClaims claims){
		this.jwtClaims = claims;
	}
	
	@Override
	public String getName() {
		if (jwtClaims != null) {
			try {
				return jwtClaims.getSubject();
			} catch (MalformedClaimException e) {
				return null;
			}
		}
		return null;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		List<GrantedAuthority> roles = new ArrayList<>();
		roles.add(new SimpleGrantedAuthority("ROLE_USER"));
		return Collections.unmodifiableList(roles);
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		if (jwtClaims != null){
			return jwtClaims.toJson();
		}
		return null;
	}

	@Override
	public Object getPrincipal() {		
		return getName();
	}

	@Override
	public boolean isAuthenticated() {
		return authenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		authenticated = isAuthenticated;		
	}

}
