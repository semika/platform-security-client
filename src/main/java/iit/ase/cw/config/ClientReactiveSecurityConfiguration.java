package iit.ase.cw.config;

import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import iit.ase.cw.authenticator.ThaproReactiveSecurityContextRepository;
import iit.ase.cw.service.ThaproUserDetailsPopulateService;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_CLIENT_ENABLED, havingValue = "true")
public class ClientReactiveSecurityConfiguration {

    private ThaproUserDetailsPopulateService thaproUserDetailsPopulateService;

    private ThaproReactiveSecurityContextRepository thaproReactiveSecurityContextRepository;

    public ClientReactiveSecurityConfiguration(ThaproUserDetailsPopulateService thaproUserDetailsPopulateService,
                                               ThaproReactiveSecurityContextRepository thaproReactiveSecurityContextRepository) {
        this.thaproUserDetailsPopulateService = thaproUserDetailsPopulateService;
        this.thaproReactiveSecurityContextRepository = thaproReactiveSecurityContextRepository;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        http.authorizeExchange(exchanges -> exchanges.pathMatchers("/login/**").permitAll()
                        .anyExchange().authenticated())
                .csrf(csrfSpec -> csrfSpec.disable()) //Will appy CSRF filter
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
                .formLogin(formLoginSpec -> formLoginSpec.disable())
                .logout(logoutSpec -> logoutSpec.disable())
                .securityContextRepository(thaproReactiveSecurityContextRepository);
        return http.build();

        //http.securityContextRepository(thaproReactiveSecurityContextRepository);

//        http.exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
//                .authenticationEntryPoint((serverWebExchange, authenticationException) ->
//                        Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
//                .accessDeniedHandler((serverWebExchange, authenticationException) ->
//                        Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN))));


        //Handle exceptions
//        http.exceptionHandling()
//            .authenticationEntryPoint((serverWebExchange, authenticationException)
//                -> Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
//            .accessDeniedHandler((serverWebExchange, authenticationException)
//                -> Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN)));

        //return http.build();
    }
}
