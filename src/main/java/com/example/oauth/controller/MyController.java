package com.example.oauth.controller;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.time.Instant;
import java.util.Map;
import java.util.StringJoiner;


@RestController
public class MyController {


    @GetMapping("/")
    public String greet(){
        return "hello from venkatesh application via sign with google";
    }



    @GetMapping("/client-id")
    public String getClientId(@AuthenticationPrincipal OidcUser oidcUser, HttpSession session) {
        OidcIdToken idToken = oidcUser.getIdToken();

        // Extract the client ID from the 'aud' claim
        String clientId = idToken.getAudience().stream()
                .findFirst() // Assuming the client ID is the first audience
                .orElse("Client ID not found");

        return "Client ID: " + clientId;
    }

    @GetMapping("/details")
    public String getUserDetails(@AuthenticationPrincipal OidcUser oidcUser, HttpSession session) {
        if (oidcUser != null) {
            String username = oidcUser.getName();
            String email = oidcUser.getEmail();
            final OidcIdToken idToken = oidcUser.getIdToken();

            // Store these in session if needed
            session.setAttribute("username", username);
            session.setAttribute("email", email);

            return username + ":" + email;
        } else {
            return "No user is authenticated.";
        }
    }

    @GetMapping("/token-info")
    public String getTokenInfo(@AuthenticationPrincipal OidcUser oidcUser) {
        OidcIdToken idToken = oidcUser.getIdToken();

        // Extract basic information
        String tokenValue = idToken.getTokenValue();
        Instant issuedAt = idToken.getIssuedAt();
        Instant expiresAt = idToken.getExpiresAt();

        // Extract claims
        Map<String, Object> claims = idToken.getClaims();
        String subject = (String) claims.get("sub");
        String email = (String) claims.get("email");
        Boolean emailVerified = (Boolean) claims.get("email_verified");

        // Construct a response or perform further actions
        return "Token Value: " + tokenValue + "\n" +
                "Issued At: " + issuedAt + "\n" +
                "Expires At: " + expiresAt + "\n" +
                "Subject: " + subject + "\n" +
                "Email: " + email + "\n" +
                "Email Verified: " + emailVerified;
    }


    @PostMapping("/extract-claims")
    public String extractClaimsAsString(@RequestBody Map<String, String> requestBody) {
        String clientIdToken = requestBody.get("clientId");

        try {
            // Parse the token
            SignedJWT signedJWT = SignedJWT.parse(clientIdToken);

            // Extract the claims
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // Get all claims as a Map
            Map<String, Object> claims = claimsSet.getClaims();

            // Create a formatted string with all the claims
            StringJoiner claimsString = new StringJoiner(", ", "{", "}");
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                claimsString.add(entry.getKey() + ": " + entry.getValue().toString());
            }

            return claimsString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }







}
