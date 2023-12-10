package iit.ase.cw.service;

import iit.ase.cw.platform.common.security.model.AuthenticationRequest;
import iit.ase.cw.platform.common.security.model.ThaproUser;

import org.springframework.security.core.userdetails.UserDetails;

public interface ThaproUserDetailsPopulateService {

     ThaproUser findByUsername(AuthenticationRequest username);
}
