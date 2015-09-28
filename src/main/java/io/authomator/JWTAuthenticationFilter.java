package io.authomator;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;


public class JWTAuthenticationFilter extends GenericFilterBean {
    
	JWTAuthenticationService jwtAuthenticationService;
    
	
	public JWTAuthenticationFilter(JWTAuthenticationService jwtAuthenticationService){
		this.jwtAuthenticationService = jwtAuthenticationService;
	}
	
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
    		FilterChain chain) throws IOException, ServletException {
    	
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        try {
            Authentication authentication = jwtAuthenticationService.getAuthenticationFromBearer(httpServletRequest);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
        catch (Exception e){
        	httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        	httpServletResponse.getWriter().printf("JWT Authentication problem: %s", e.getMessage());
        }
    }
}