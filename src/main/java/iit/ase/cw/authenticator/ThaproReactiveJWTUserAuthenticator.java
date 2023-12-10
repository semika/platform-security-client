package iit.ase.cw.authenticator;

import iit.ase.cw.model.ThaproAuthentication;
import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.platform.common.security.model.AuthenticationRequest;
import iit.ase.cw.platform.common.security.model.ThaproUser;
import iit.ase.cw.service.ThaproUserDetailsPopulateService;

import iit.ase.cw.util.ThaproJwtTokenHandler;
import iit.ase.cw.util.ThaproSecurityUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.core.JsonProcessingException;

import reactor.core.publisher.Mono;

public class ThaproReactiveJWTUserAuthenticator implements ThaproReactiveUserAuthenticator {

    private ThaproUserDetailsPopulateService thaproUserDetailsPopulateService;
    private ThaproJwtTokenHandler jwtUtil;

    public ThaproReactiveJWTUserAuthenticator(ThaproUserDetailsPopulateService thaproUserDetailsPopulateService,
                                              ThaproJwtTokenHandler jwtUtil) {
        this.thaproUserDetailsPopulateService = thaproUserDetailsPopulateService;
        this.jwtUtil = jwtUtil;
    }
    @Override
    public Mono<SecurityContext> authenticate(ServerWebExchange serverWebExchange) {
        // Get authorization header and validate
        try {
            SecurityContext securityContext = handleAuthentication(serverWebExchange);
            return Mono.create((sink) -> sink.success(securityContext));
        } catch (Exception exception) {
            exception.printStackTrace(); //TODO replace with proper loggin mechenisum
            return Mono.empty(); //Not security context is created. 401 will be returned
        }
    }

    private SecurityContext handleAuthentication(ServerWebExchange serverWebExchange) {

        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

        // Get authorization header and validate
        String jwt = ThaproSecurityUtil.getBearerAuthHeader(serverWebExchange, HttpHeaders.AUTHORIZATION);
        if (jwt == null) {
            throw new RuntimeException("Authentication error. Authorization header missing");
        }

        //Extract login credentials from browser JWT
        try {
            AuthenticationRequest authenticationRequest = jwtUtil.extractClientToken(jwt);

            //Load the user and role from the database.
            ThaproUser thaproUser = thaproUserDetailsPopulateService.findByUsername(authenticationRequest.getUsername());
            if (thaproUser == null) {
                throw new RuntimeException("Authentication error. Unable to find the user");
            }

            //validate password, check the user provided password against the database one.
            Boolean isValidPassword = validatePassword(authenticationRequest.getPassword(), thaproUser.getPassword());
            if (!isValidPassword) {
                throw new RuntimeException("Authentication error. Invalid login credentials");
            }

            ThaproAuthentication authenticated = ThaproAuthentication.builder().
                thaproUser(thaproUser)
                .isAuthenticated(true)
                .userSecret(thaproUser.getPassword()).build();

            //populate security context holder
            securityContext.setAuthentication(authenticated);

            //create new JWT token and set JWT header for downstream services.
            String serverJwt = jwtUtil.createToken(authenticated);
            serverWebExchange.getRequest().mutate().headers((httpHeaders -> {
                httpHeaders.add(ThaproSecurityConstant.Header.THAPRO_AUTHENTICATED_HEADER, serverJwt);
            }));

        } catch (JsonProcessingException e) {
            throw new RuntimeException("Authentication error. Unable to extract login credentials", e);
        }

        return securityContext;
    }

    private Boolean validatePassword(String requestPassword, String dbPassword) {
        String formattedPW = dbPassword.replace("{noop}", "");
        return requestPassword.equals(formattedPW);
    }
}
