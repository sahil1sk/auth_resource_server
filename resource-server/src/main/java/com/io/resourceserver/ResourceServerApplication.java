package com.io.resourceserver;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.userdetails.User;


@SpringBootApplication
@EnableResourceServer
@RestController
public class ResourceServerApplication {

    @GetMapping("/api/users/me")
    public ResponseEntity<Map> profile() // profile(Authentication value) => Another way to get the data of login user using credentials
    {
        //Build some dummy data to return for testing
//        User u = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Authentication user = SecurityContextHolder.getContext().getAuthentication();
//        String username = loggedInUser.getName();
        
        System.out.println(SecurityContextHolder.getContext().getAuthentication().toString());
        String email = user.getName() + "@howtodoinjava.com";
 
        Map profile = new HashMap<>();
        profile.put("username", user.getName());
        profile.put("email", email);
        
        System.out.println("*********************");
        System.out.println(user.getCredentials());
        System.out.println(user.getDetails());
        System.out.println(user.getPrincipal());
        System.out.println(user.getAuthorities());
        System.out.println("************************");
        
        return ResponseEntity.ok(profile);
    }
    
    @GetMapping("/test")
    public String getData() {
    	System.out.println(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    	return "Test Success Full";
    }
    
    @GetMapping("/open")
    public String openData() {
    	return "Open To all without Auth";
    }
	
	public static void main(String[] args) {
		SpringApplication.run(ResourceServerApplication.class, args);
	}

}


@Configuration
class OAuth2ResourceServer extends ResourceServerConfigurerAdapter 
{
    @Override
    public void configure(HttpSecurity http) throws Exception {    	
    	http.csrf().disable()
    	.authorizeRequests().antMatchers("/api/**", "/api/upload").hasRole("ADMIN").antMatchers("/open").permitAll()
    	.anyRequest().authenticated().and()
    	.sessionManagement()
    	.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }
}

class CustomPrincipal implements Serializable {
	
	private static final long serialVersionUID = 1L;
	private String username;
	private String email;
	
	public CustomPrincipal() {
		
	}

	public CustomPrincipal(String username, String email) {
		this.username = username;
		this.email = email;	
	}

	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
}

//@Configuration
//@Order(1)
//class SecurityConfig extends WebSecurityConfigurerAdapter {
//  
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
////        http
////            .antMatcher("/**")
////                .authorizeRequests()
////                .antMatchers("/oauth/authorize**", "/login**", "/error**")
////                .permitAll()
////            .and()
////                .authorizeRequests()
////                .anyRequest().authenticated()
////            .and()
////                .formLogin().permitAll();
//        
//    	
//    	http.csrf().disable()
//    	.authorizeRequests().antMatchers("/api/**", "/api/upload").hasAuthority("ADMIN")
//    	.anyRequest().authenticated().and()
//    	.sessionManagement()
//    	.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//    }
//  
////    @Override
////    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
////        auth
////            .inMemoryAuthentication()
////            .withUser("humptydumpty").password(passwordEncoder().encode("123456")).roles("USER");
////    }
////      
////    @Bean
////    public BCryptPasswordEncoder passwordEncoder(){ 
////        return new BCryptPasswordEncoder(); 
////    }
//}

