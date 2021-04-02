package com.security.springsecurityboot.controller;

import java.util.Collection;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetController {
	
	@GetMapping("/secured/basicauth/greet/{name}")
	public String greetSecuredWithBasicAuth(@PathVariable String name, ModelMap model) {		
		String greet ="";
		String clientId = "";
	    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	    if(authentication instanceof UsernamePasswordAuthenticationToken) {
	    	UsernamePasswordAuthenticationToken uidPwdtoken = (UsernamePasswordAuthenticationToken) authentication;
	    	clientId = uidPwdtoken.getName();
	    	System.out.println("client id : " + clientId);
			System.out.println("Principal : " + uidPwdtoken.getPrincipal());
			System.out.println("=========================================");
			greet = "Hello!!! " + name + " How are You?" + "Authentication CLient ID " + clientId; 
	    }	    
		return greet;
	}

	@PreAuthorize("hasAuthority('SCOPE_application_read')")
	@GetMapping("/secured/oauth/greet/withreadscope/{name}")
	public String greetSecuredWithReadScope(@PathVariable String name, ModelMap model) {		
		String greet ="";
		String clientId = "";
	    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	    if(authentication instanceof UsernamePasswordAuthenticationToken) {
	    	UsernamePasswordAuthenticationToken uidPwdtoken = (UsernamePasswordAuthenticationToken) authentication;
	    	clientId = uidPwdtoken.getName();
	    	System.out.println("client id : " + clientId);
			System.out.println("Principal : " + uidPwdtoken.getPrincipal());
	    } else if (authentication instanceof JwtAuthenticationToken) {
	    	JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
	    	System.out.println("=========================================");
	    	clientId = jwtToken.getName();
	    	System.out.println("client id : " + clientId);
			System.out.println("Principal : " + jwtToken.getPrincipal());
			System.out.println("Token : " + jwtToken.getToken().getTokenValue());
			Collection<GrantedAuthority> collection = jwtToken.getAuthorities();
			// for loop
			 for (GrantedAuthority s : collection) {
			        System.out.println("Scope :  " + s.getAuthority());
			}
			System.out.println("=========================================");			
	    }
	    greet = "Hello!!! " + name + " How are You?" + "Authentication CLient ID " + clientId; 
		return greet;
	}
	
	@PreAuthorize("hasAuthority('SCOPE_application_write')")
	@GetMapping("/secured/oauth/greet/withwritescope/{name}")
	public String greetSecuredWithWriteScope(@PathVariable String name, ModelMap model,
			JwtAuthenticationToken authentication) {
		System.out.println("=========================================");		
		System.out.println("client id : " + authentication.getName());
		System.out.println("Principal : " + authentication.getPrincipal());
		System.out.println("Token : " + authentication.getToken().getTokenValue());
		Collection<GrantedAuthority> collection = authentication.getAuthorities();
		// for loop
		 for (GrantedAuthority s : collection) {
		        System.out.println("Scope :  " + s.getAuthority());
		}
		System.out.println("=========================================");
		String greet = "Hello!!! " + name + " How are You?";
		return greet;
	}


	@GetMapping("/unsecured/greet/{name}")
	public String greetUnsecured(@PathVariable String name, ModelMap model) {
		String greet = "Hello!!! " + name + " you are not Authenticated. ";
		return greet;
	}
}
