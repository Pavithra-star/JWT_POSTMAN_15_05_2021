package com.example.demo.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtil {
	 private String SECRETE_KEY = "pavithra";
	 
	 public String extracUsername(String token) {
		 return extractClaim(token ,Claims::getSubject);
	 }
	 
	 public Date extractExpiration(String token) {
		 return extractClaim(token , Claims::getExpiration);
	 }
	 
	 public <T> T extractClaim(String token , Function<Claims,T> claimsResolover) {
		final Claims claims = extractAllClaims(token);
		 return claimsResolover.apply(claims);
	}
	 private Claims extractAllClaims(String token) {
		 return Jwts.parser().setSigningKey(SECRETE_KEY).parseClaimsJws(token).getBody();
	 }
	 
	 private Boolean isTokenExpired(String token) {
		 return extractExpiration(token).before(new Date());
	 }
	 //create the token when when the is authenticated
	 public String generateToken(UserDetails userDetails) {
		 Map<String ,Object> claims = new HashMap<>();
		 return createToken(claims,userDetails.getUsername());
	 }

//	private String createToken(Map<String, Object> claims, String username) {
//		Map<String,Object> claims = new HashMap<>();
//		return createToken(claims,userDetails.getUsrnmae());
//	}
	 private String createToken(Map<String, Object> claims, String subject) {

		 

	        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
	                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
	                .signWith(SignatureAlgorithm.HS256, SECRETE_KEY).compact();
	    }
	    //validating the token
	    public Boolean validateToken(String token, UserDetails userDetails) {
	        final String username = extracUsername(token);
	        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	    }
	}
