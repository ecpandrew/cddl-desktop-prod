package io.moquette.broker;

import br.ufma.lsdi.security.SecurityServiceImpl;

import javax.net.ssl.SSLContext;

public class SSLContextCreatorHolder implements ISslContextCreator {

    private SecurityServiceImpl securityService;
    public SSLContextCreatorHolder(SecurityServiceImpl sec){
        this.securityService = sec;
    }

    @Override
    public SSLContext initSSLContext() throws Exception {
        return securityService.getSSLContext();
    }
}
