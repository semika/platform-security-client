package iit.ase.cw.config;

import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.service.UserDetailPopulateService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import iit.ase.cw.authenticator.ThaproReactiveSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
@ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_CLIENT_ENABLED, havingValue = "true")
public class ClientReactiveSecurityConfiguration {

    public ClientReactiveSecurityConfiguration() {}

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            ThaproReactiveSecurityContextRepository thaproReactiveSecurityContextRepository) {

        http.authorizeExchange(exchanges -> exchanges.pathMatchers("/login/**").permitAll()
                        .anyExchange().authenticated())
                .csrf(csrfSpec -> csrfSpec.disable()) //Will appy CSRF filter
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
                .formLogin(formLoginSpec -> formLoginSpec.disable())
                .logout(logoutSpec -> logoutSpec.disable())
                .securityContextRepository(thaproReactiveSecurityContextRepository);
        return http.build();
    }

    @Bean
    public ThaproReactiveSecurityContextRepository thaproReactiveSecurityContextRepository() {
        return new ThaproReactiveSecurityContextRepository();
    }

    @Bean
    @ConditionalOnMissingBean
    UserDetailPopulateService userDetailPopulateService() {
        return new UserDetailPopulateService();
    }
}
