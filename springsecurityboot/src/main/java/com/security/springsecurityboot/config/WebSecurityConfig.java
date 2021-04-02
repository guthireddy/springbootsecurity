package com.security.springsecurityboot.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.authentication.builders.*;  
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
//import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth)
      throws Exception {
    auth
    .inMemoryAuthentication()
    .withUser("client1").password("{noop}Toronto54321")
    .authorities("ROLE_USER");
    
    // Value = "pjgC8awaEQwi58WraKuKoJRcVV0Zww8CAXyJvtKO" SHA256 = 5c40c02d389b6b5c124b09a839f5bee426d2d9e64db192bfc77cb01c9d7099c7
    //{sha256}d760e50481ace46dd565ed19f03aa82834c2b5d974a60b6a0f9402548ca79171
    // {noop}Toronto54321
  }

	
	 
	protected void configure(HttpSecurity http) throws Exception {
		
		// Working code -- With Oauth2 JWT token with OKTA 
		
//		http.authorizeRequests()
//		.antMatchers("/unsecured/**").permitAll()
//		.antMatchers("/secured/**").authenticated()
//				.anyRequest().authenticated().and()
//				.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())));
		
		// basic Auth
		
		 http
		    .authorizeRequests()
		    .antMatchers("/unsecured/**").permitAll()
		    .antMatchers("/secured/**").authenticated()
		    .and()
		    	.httpBasic().realmName("Your App")
		    .and()
		    	.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())));
	}
	 
	
//	@Bean
//	public CustomBasicAuthenticationProvider myAuthProvider() throws Exception {
//		CustomBasicAuthenticationProvider provider = new CustomBasicAuthenticationProvider();
//	    provider.setPasswordEncoder(passwordEncoder());
//	    provider.setUserDetailsService();
//	    return provider;
//	}
	
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(myAuthProvider());
//    }
//
//	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
//	}
//
//	protected void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable().authorizeRequests().antMatchers("/unsecured/**").permitAll().antMatchers("/secured/**")
//				.authenticated().and().httpBasic();
//				//.and()
//				//.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())));
//	}
//
//	@Bean
//	public CustomBasicAuthenticationEntryPoint getBasicAuthEntryPoint() {
//		return new CustomBasicAuthenticationEntryPoint();
//	}

	private JwtDecoder jwtDecoder() {
		String issuerUri = "https://dev-964515.okta.com/oauth2/default";
		NimbusJwtDecoder jwtDecoder = null;
		try {
			jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuerUri);
			OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
			OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer,
					new AudienceValidator());

			jwtDecoder.setJwtValidator(withAudience);
			System.out.println("Created JWtDecoder Successfully");
		}catch(Exception e) {	
			e.printStackTrace();
		}
		return jwtDecoder;
	}

}