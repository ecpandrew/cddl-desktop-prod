package io.moquette.broker.security;

import br.ufma.lsdi.security.SecurityServiceImpl;
import br.ufma.lsdi.security.helpers.Log;
import io.moquette.broker.subscriptions.Topic;

import java.util.ArrayList;
import java.util.List;
public class CDDLAuthorizatorPolicy implements IAuthorizatorPolicy {

    SecurityServiceImpl securityService;
    List<String> rules;
    List<CDDLAuthorization> authorizations;


    public CDDLAuthorizatorPolicy(SecurityServiceImpl sec){
        this.securityService = sec;
        this.authorizations = new ArrayList<CDDLAuthorization>();
        loadRules();
        Log.debug("Autorization", "Using security service ACL.");
    }

    private void loadRules() {
        this.rules = securityService.getCDDLRules();
        for (String rule: rules) {
            if (rule != null && !rule.isEmpty()) {
                String[] split = rule.split(" ");
                String clientID = split[0];
                String topic = split[1];
                String permission = split[2];
                authorizations.add(new CDDLAuthorization(clientID, topic, permission));
            }
        }
    }


    @Override
    public boolean canRead(Topic topic, String user, String client) {
        String cliente = client.substring(0,client.length() - 6);
//        System.out.println(client + "CAN'T READ topic: " + topic.toString());
//        return true;
        for (CDDLAuthorization authorization: authorizations) {
            if(authorization.grantRead(cliente, topic.toString())){
                System.out.println(
                        cliente + " is authorized to subscribe on topic: " + topic.toString()
                );
                return true;
            }
        }
        System.out.println("Access Denied: " +cliente+ " is not allowed to subscribe on topic: " + topic.toString());
        return false;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
//        System.out.println(client + "CAN'T WRITE topic: " + topic.toString());
//        return true;
        String cliente = client.substring(0,client.length() - 6);
        for (CDDLAuthorization authorization: authorizations) {
            if(authorization.grantWrite(cliente, topic.toString())){
                System.out.println(
                        cliente + " is authorized to publish on topic: " + topic.toString()
                );
                return true;
            }
        }
        System.out.println("Access Denied: " +cliente+ " is not allowed to publish on topic: " + topic.toString());

        return false;
    }

}