package net.codejava;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public UserDetailsService userDetailsService() {
		return new UserDetailsServiceImpl();
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		
		return authProvider;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().disable().authorizeRequests()
			.antMatchers("/home", "/login**","/callback/", "/webjars/**", "/error**", "/oauth2**").permitAll()
			.anyRequest().authenticated()
			.and()
			.formLogin().permitAll()
				.loginPage("/login")
				.usernameParameter("email")
				.passwordParameter("pass")
				.defaultSuccessUrl("/list")
			.and()
			.oauth2Login()
				.loginPage("/login")
				.userInfoEndpoint()
					.userService(oauthUserService)
				.and()
				.successHandler(new AuthenticationSuccessHandler() {
					
					@Override
					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
							Authentication authentication) throws IOException, ServletException {
						System.out.println("AuthenticationSuccessHandler invoked");
						System.out.println("Authentication name: " + authentication.getName());
						CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
						
						userService.processOAuthPostLogin(oauthUser.getEmail());
						
						response.sendRedirect("/list");
					}
				}).failureHandler(new AuthenticationFailureHandler() {
					
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
							AuthenticationException exception) throws IOException, ServletException {
						// TODO Auto-generated method stub
						System.out.println("Failed the oauth : "+exception.getMessage());
						exception.printStackTrace();
					}
				}).failureUrl("/403")
				
			.and()
	.logout().logoutSuccessUrl("/login").permitAll()
			.and()
			.exceptionHandling().accessDeniedPage("/403")

			;
//		http.rememberMe().tokenRepository(new PersistentTokenRepository());
	}
	
	@Autowired
	private CustomOAuth2UserService oauthUserService;
	
	@Autowired
	private UserService userService;
}
