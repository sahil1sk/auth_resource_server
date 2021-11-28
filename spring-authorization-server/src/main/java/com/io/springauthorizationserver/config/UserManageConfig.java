package com.io.springauthorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
//@EnableWebSecurity
public class UserManageConfig extends WebSecurityConfigurerAdapter {
	
	@Bean
	public UserDetailsService userDetailsService() {
		var user = new InMemoryUserDetailsManager();
		
		user.createUser(
				User.withUsername("Mark")
				.password(pe().encode("1234"))
				.authorities("ROLE_ADMIN").build() //  ("ROLE_ADMIN", "ROLE_USER")
				);
		
		return user;
	}
	
	@Bean
	public PasswordEncoder pe() {
		return new BCryptPasswordEncoder();
	}
	
	
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable()
//		.authorizeRequests().antMatchers("/check_token").permitAll()
//		.anyRequest().authenticated().and().formLogin();

		
		http.csrf().disable().antMatcher("/")
		.authorizeHttpRequests()
		.anyRequest().authenticated().and().formLogin();
//		http.formLogin();
//		http.authorizeHttpRequests().anyRequest().authenticated();
	}
}
