package iit.ase.cw.config;

import iit.ase.cw.authenticator.ThaproReactiveBasicUserAuthenticator;
import iit.ase.cw.authenticator.ThaproReactiveJWTUserAuthenticator;
import iit.ase.cw.authenticator.ThaproReactiveSecurityContextRepository;
import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.service.ThaproUserDetailsPopulateService;

import iit.ase.cw.service.UserDetailPopulateService;
import iit.ase.cw.util.ThaproJwtTokenHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ThaproReactiveSecurityAutoConfiguration {

    @Bean
    public ThaproJwtTokenHandler jwtUtil() {
        return new ThaproJwtTokenHandler();
    }

    @Bean
    @ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_CLIENT_BASIC_AUTH_ENABLED, havingValue = "true")
    public ThaproReactiveBasicUserAuthenticator thaproReactiveBasicUserAuthenticator(
        ThaproUserDetailsPopulateService thaproUserDetailsPopulateService, ThaproJwtTokenHandler jwtUtil) {
        return new ThaproReactiveBasicUserAuthenticator(thaproUserDetailsPopulateService, jwtUtil);
    }

    @Bean
    @ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_CLIENT_JWT_AUTH_ENABLED, havingValue = "true")
    public ThaproReactiveJWTUserAuthenticator thaproReactiveJWTUserAuthenticator(
        ThaproUserDetailsPopulateService thaproUserDetailsPopulateService, ThaproJwtTokenHandler jwtUtil) {
        return new ThaproReactiveJWTUserAuthenticator(thaproUserDetailsPopulateService, jwtUtil);
    }
}
