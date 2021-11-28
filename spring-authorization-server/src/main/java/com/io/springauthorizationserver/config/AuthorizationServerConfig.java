package com.io.springauthorizationserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

//Grant Types => 
//	authorization_code
//	implicit (Now it is authorization_code)
//	client_credentials
//	refresh_token
//	password --> deprecated 

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	PasswordEncoder pe;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		clients.inMemory()												// For giving token Validity Seconds customly 
		.withClient("cleintId").secret(pe.encode("secretId")).accessTokenValiditySeconds(80000)
		.scopes("read").authorizedGrantTypes("password", "refresh_token")
		.and()
		.withClient("cleintId3").secret(pe.encode("secretId3"))
		.scopes("read").authorizedGrantTypes("password", "authorization_code", "refresh_token")
		.and()
		 .withClient("cleintId4").secret(pe.encode("secretId4"))
		.scopes("read").authorizedGrantTypes("client_credentials")
		.and()
		.withClient("cleintId2").secret(pe.encode("secretId4"))
		.scopes("read").authorizedGrantTypes("authorization_code").redirectUris("http://localhost:8083");
		
		
		// WITH PASSWORD grant type
		// url => http://localhost:7000/oauth/token?grant_type=password&username=Mark&password=1234&scope=read 
		// with basic auth where username is clientid and password is client secretId
		
		// WITH AUTHORIZATION CODE grant type // For authorization code we are using redirectUri to send the token to that uri
		
		// Here first login on authoirzation server
		// login => http://localhost:7000/login
		
		// then authorize and generate code
		// authorize url => http://localhost:7000/oauth/authorize?response_type=code&client_id=cleintId2&scope=read
		
		// then using code generate access token REMEBER you can use the code only once
		// geratetoken => http://localhost:7000/oauth/token?grant_type=authorization_code&code=codeReceivedFromGenerateCode&scope=read
		// with basic auth where username is clientid and password is client secretId
		
		// REFRESH TOKEN grant type (this grant type is always used with some other grant type not alone)
		// this grant type is used to generate refresh token which helps to generate new token
		// url => http://localhost:7000/oauth/token?grant_type=refresh_token&refresh_token=ebe70d7b-da06-44f6-bd38-b54026ae0ce2
		// with basic auth where username is clientid and password is client secretId
		
		// CLIENT CREDENTIALS Grant Type
		// =>  In this we normally provide our clientId as client Password and getting our access token like registering client and getting access token
		// url => 
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		// Now this will try to call to other authentication existing in our UserManageConfig File and try to authenticate our user
		endpoints.authenticationManager(authenticationManager);
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		// isAuthenticated()  // we need to give clientId and secretId while checking token
		// permitAll() // means we need to given client and secret id while checking token

		// By Default Check token url is disabled we need to enable that by giving given settings
	    security.allowFormAuthenticationForClients().checkTokenAccess("isAuthenticated()");       

	}
	
}
