package iit.ase.cw.authenticator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

public class ThaproReactiveSecurityContextRepository implements ServerSecurityContextRepository {

    @Autowired
    private ThaproReactiveUserAuthenticator thaproReactiveUserAuthenticator;

    @Override
    public Mono<Void> save(ServerWebExchange serverWebExchange, SecurityContext securityContext) {
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange serverWebExchange) {
        return thaproReactiveUserAuthenticator.authenticate(serverWebExchange);
    }
}
