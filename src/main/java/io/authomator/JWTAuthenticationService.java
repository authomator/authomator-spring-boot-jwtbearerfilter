package io.authomator;

import javax.servlet.http.HttpServletRequest;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.authomator.jwt.exception.JWTAuthenticationException;

@Component
public class JWTAuthenticationService {

	private final String authorizationSchema = "Bearer";
	private final int authorizationSchemaLength = 6;
	
	@Value("${jwt.authentication.secret}")
	private String secret = "";
	
	@Value("${jwt.authentication.issuer}")
	private String issuer = "";
	
	@Value("${jwt.authentication.audience}")
	private String audience = "";
	
	private JwtConsumer jwtConsumer = null;
	
	private JwtConsumer getJwtConsumer(){
		if (jwtConsumer != null) {
			return jwtConsumer;
		}

		jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer(issuer)
                .setExpectedAudience(audience)
                .setJwsAlgorithmConstraints(AlgorithmConstraints.DISALLOW_NONE)
                .setVerificationKey(new HmacKey(secret.getBytes()))
                .build();
		
		return jwtConsumer;	
	}
	
	public Authentication getAuthenticationFromBearer(HttpServletRequest request){
	
        String stringToken = request.getHeader("Authorization");
        if (stringToken == null) {
            return null;
        }
            
        if (stringToken.indexOf(authorizationSchema) == -1) {
        	return null;
        }
        stringToken = stringToken.substring(authorizationSchemaLength).trim();
		        
        try
        {
            JwtClaims jwtClaims = getJwtConsumer().processToClaims(stringToken);
            return new JWTAuthentication(jwtClaims);
        }
        catch (InvalidJwtException e)
        {
            throw new JWTAuthenticationException();
        }        		
	}
}