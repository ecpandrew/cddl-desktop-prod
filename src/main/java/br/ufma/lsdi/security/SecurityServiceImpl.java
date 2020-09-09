package br.ufma.lsdi.security;




import br.ufma.lsdi.security.helpers.CsrHelper;
import br.ufma.lsdi.security.helpers.Log;

import br.ufma.lsdi.security.helpers.TxtFileHelper;
import org.spongycastle.pkcs.PKCS10CertificationRequest;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Created by andrecardoso on 28/01/2020.
 */

public class SecurityServiceImpl {

    public static final String ALL_TOPICS = "all_topics";
    public static final String QUERY_TOPIC = "query_topic";
    public static final String CANCEL_QUERY_TOPIC = "cancel_query_topic";
    public static final String QUERY_RESPONSE_TOPIC = "query_response_topic";
    public static final String COMMAND_TOPIC = "command_topic";
    public static final String EVENT_QUERY_TOPIC = "event_query_topic";
    public static final String EVENT_QUERY_RESPONSE_TOPIC = "event_query_response_topic";
    public static final String SERVICE_TOPIC = "service_topic";
    public static final String SERVICE_INFORMATION_TOPIC = "service_information_topic";
    public static final String LIVELINESS_TOPIC = "liveliness_topic";
    public static final String CONNECTION_CHANGED_STATUS_TOPIC = "connection_changed_status_topic";
    public static final String RENDEZVOUS_TOPIC = "rendezvous_topic";
    public static final String OBJECT_FOUND_TOPIC = "object_found_topic";
    public static final String OBJECT_CONNECTED_TOPIC = "object_connected_topic";
    public static final String OBJECT_DISCONNECTED_TOPIC = "object_disconnected_topic";
    public static final String OBJECT_DISCOVERED_TOPIC = "object_discovered_topic";

    private String[] premade_cddl_topics = new String[]{
            QUERY_TOPIC,CANCEL_QUERY_TOPIC,QUERY_RESPONSE_TOPIC,COMMAND_TOPIC,EVENT_QUERY_TOPIC,
            EVENT_QUERY_RESPONSE_TOPIC,SERVICE_TOPIC,SERVICE_INFORMATION_TOPIC,LIVELINESS_TOPIC,
            CONNECTION_CHANGED_STATUS_TOPIC,OBJECT_FOUND_TOPIC,OBJECT_CONNECTED_TOPIC,OBJECT_DISCONNECTED_TOPIC,
            OBJECT_DISCOVERED_TOPIC, RENDEZVOUS_TOPIC, ALL_TOPICS};


    private char[] password;
    private final String keyStoreType = "PKCS12";
    private final String algorithm = "RSA";
    private final String keystoreFileInternal = "securitykeystore.p12";
    private final String ACLFile = "ACL.txt";
    private final String csrFileInternal = "client.csr";
    private final String CLIENT_ALIAS = "client_cert";
    private final String CA_ALIAS = "ca_cert";

    private KeyStore keyStore;
    private KeyPair keyPair;
    private String path;



    public SecurityServiceImpl(String pwd) throws IOException {
        this.password = pwd.toCharArray();
        this.path = new File(".").getCanonicalPath();;
        try {
            this.keyStore = KeyStore.getInstance(keyStoreType);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        if(!isKeystoreFilePresent(keystoreFileInternal)){
            Log.debug("debug", "Keystore txt file not exists.");
            createAndSaveKeystoreInTxtFile();
            Log.debug("debug", "Keystore txt file created.");
        }else {
            Log.debug("debug", "Keystore txt file found.");
            loadKeystore();
            Log.debug("debug", "Keystore txt file loaded.");
        }
        if(!isACLFilePresent(ACLFile)){
            createACLFile();
        }
    }

    private boolean contain(String topic_name){

        for (String name: premade_cddl_topics) {
            if(name.equals(topic_name)){
                return true;
            }

        }
        return false;
    }



    private boolean isKeystoreFilePresent(String fileName) {
        return TxtFileHelper.fileExists(path, fileName);
    }

    private boolean isACLFilePresent(String fileName) {
        return TxtFileHelper.fileExists(path, fileName);
    }


    private void eraseTxtFileContent(String fileName){
        TxtFileHelper.eraseTxtFileContent(path, fileName);
    }


    private void createAndSaveKeystoreInTxtFile() {
        Log.debug("Info","Creating Keystore." );
        TxtFileHelper.createAndSaveKeystoreInTxtFile(path, keyStoreType, password, keystoreFileInternal);

    }

    private void createACLFile(){
        Log.debug("Info","Creating Keystore." );
        TxtFileHelper.createACLFile(path, ACLFile);

    }

    private void loadKeystore(){
        File file = new File(path, keystoreFileInternal);
        try {
            FileInputStream fis = new FileInputStream(file);
            keyStore.load(fis, password);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }



    private void generateKeyPair() {
        try {
            this.keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }



    public String generateCSR(String CN, String OU, String O, String L, String S, String C) {
        if(keyPair==null){
            generateKeyPair();
        }
        PKCS10CertificationRequest csr = CsrHelper.generateCSR(keyPair, CN, OU, O);
        byte  CSRder[] = new byte[0];
        try {
            CSRder = csr.getEncoded();
            saveCSRInTxtFile(CSRder);
            saveKeyPair(path);

        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(CSRder);
    }


    private void saveCSRInTxtFile(byte[] csr) {
        TxtFileHelper.saveCSRInTxtFile(path,csrFileInternal, csr);
    }

    private void saveKeyPair(String path){

        eraseTxtFileContent("public.key");
        eraseTxtFileContent("private.key");

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(path + "/public.key");
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();

            // Store Private Key.
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    privateKey.getEncoded());
            fos = new FileOutputStream(path + "/private.key");
            fos.write(pkcs8EncodedKeySpec.getEncoded());
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public void setCertificate(String fileName){
        try {
            loadKeystore();
            loadKeyPairFromTxt(path);
            File cert_file = new File(path, fileName);
            InputStream fis = new FileInputStream(cert_file);
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(bis);
            X509Certificate[] chain = {cert};
            keyStore.setKeyEntry(
                    CLIENT_ALIAS,
                    keyPair.getPrivate(),
                    password,
                    chain
            );
            eraseTxtFileContent(keystoreFileInternal);
            FileOutputStream outputStream = new FileOutputStream(new File(path,keystoreFileInternal));
            keyStore.store(outputStream, password);
            Log.debug("Debug","Cient cert added to keystore succesfully!!!!");
            outputStream.close();
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public Certificate getCertificate() {
        loadKeystore();
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(CLIENT_ALIAS, new KeyStore.PasswordProtection(password));
            return privateKeyEntry.getCertificate();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
            return null;
        }
    }


    private void loadKeyPairFromTxt(String path)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File(path + "/private.key");
        fis = new FileInputStream(path + "/private.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        keyPair = new KeyPair(publicKey, privateKey);
    }


    public boolean verifyCertificateAgainstCA(){
        X509Certificate  ca = (X509Certificate) getCACertificate();
        X509Certificate client = (X509Certificate) getCertificate();
        if(ca == null){return false;}
        if(client == null){return false;}
        return client.getIssuerX500Principal() == ca.getSubjectX500Principal();
    }

    public boolean verifyCertificateAgainstPrivateKey(){
        try {
            loadKeyPairFromTxt(path);
            PublicKey publicKey = getCertificate().getPublicKey();
            PrivateKey privateKey = keyPair.getPrivate();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            return rsaPublicKey.getModulus().equals( rsaPrivateKey.getModulus() )
                    && BigInteger.valueOf( 2 ).modPow( rsaPublicKey.getPublicExponent()
                            .multiply( rsaPrivateKey.getPrivateExponent() ).subtract( BigInteger.ONE ),
                    rsaPublicKey.getModulus() ).equals( BigInteger.ONE );
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return false;
    }


    public void setCaCertificate(String fileName) {
        try {
            File ca_file = new File(path, fileName);
            InputStream fis = new FileInputStream(ca_file);
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf;
            cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
            loadKeystore();
            keyStore.setCertificateEntry(CA_ALIAS, cert);
            eraseTxtFileContent(keystoreFileInternal);
            FileOutputStream outputStream = new FileOutputStream(new File(path, keystoreFileInternal));
            keyStore.store(outputStream, password);
            Log.debug("debug","Ca cert added to keystore succesfully!!!!");
            outputStream.close();
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            e.printStackTrace();
        }
    }


    public Certificate getCACertificate() {
        try {
            return keyStore.getCertificate("ca_cert");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }


    public SSLContext getSSLContext() throws  Exception {

        SSLContext serverContext = SSLContext.getInstance("TLS");
        loadKeystore();
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("client_cert", new KeyStore.PasswordProtection(password));
        final Certificate caCert = getCertificate();
        if(privateKeyEntry == null){throw new Exception("Can't find certificate.");}
        if(caCert == null){throw new Exception("Can't find CA certificate.");}
        // Init keystore for KeyManagerFactory
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(null, null);
        ks.setKeyEntry("server", privateKeyEntry.getPrivateKey(), password, privateKeyEntry.getCertificateChain());
        // Init KeyManagerFactory
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password);

        // Init keystore for TrustManagerFactory
        KeyStore ks2 = KeyStore.getInstance("pkcs12");
        ks2.load(null, null);
        ks2.setCertificateEntry("ca", keyStore.getCertificate("ca_cert"));
        // Init TrustManagerFactory
        final TrustManagerFactory my_trust_manager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        my_trust_manager.init(ks2);
        serverContext.init(kmf.getKeyManagers(), my_trust_manager.getTrustManagers() , new SecureRandom());
        return serverContext;
    }

    public List<String> getCDDLRules(){
        List<String> rules = new ArrayList<>();
        FileInputStream fis;
        try {
            File file = new File(path, ACLFile);
            fis = new FileInputStream(file);
            InputStreamReader isr = new InputStreamReader(fis);
            BufferedReader bufferedReader = new BufferedReader(isr);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                sb.append(line);
                rules.add(line.trim());
            }
            bufferedReader.close();
            return rules;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return rules;
    }







    public void grantPermissionByCDDLTopic(String clientID, String topic_name, String permission){
        String topic = buildTopic(topic_name);
        if(topic.equals("invalid_topic")){
            Log.debug("Authorization","Invalid CDDL topic.");
            return;
        }
        try {
            File acl = new File(path,ACLFile);
            FileOutputStream fOut = new FileOutputStream(acl, true);

            StringBuilder rule = new StringBuilder();


            if(topic.equals("all_topics")){
                rule.append(clientID).append(" ")
                        .append(topic).append(" ")
                        .append(permission).append("\n");
            }else{
                if(permission.equals("write")){
                    rule.append(clientID).append(" ")
                            .append(topic.replace("+", clientID)).append(" ")
                            .append(permission).append("\n");
                }else{
                    rule.append(clientID).append(" ")
                            .append(topic).append(" ")
                            .append(permission).append("\n");
                }
            }



            fOut.write(rule.toString().getBytes());
            fOut.close();
            Log.debug("ACESS-CONTROL", "grantServiceTopicPermission: "+rule.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }






    public void grantPermissionByCustomTopic(String clientID, String topic, String permission){
        try {

            File acl = new File(path,ACLFile);
            FileOutputStream fOut = new FileOutputStream(acl,true);
            StringBuilder rule = new StringBuilder();
            rule.append(clientID).append(" ")
                    .append(topic).append(" ")
                    .append(permission).append("\n");

            fOut.write(rule.toString().getBytes());
            fOut.close();
            Log.debug("ACESS-CONTROL", "grantServiceTopicPermission: "+rule.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    private String buildTopic(String topic_name) {
        if(topic_name.equals(ALL_TOPICS)){
            return "all_topics";
        }
        if(contain(topic_name)){
            return "mhub/+/" + topic_name;
        }
        return "invalid_topic";
    }

    private String buildServiceTopic(String serviceName){
        return "mhub/+/service_topic/"+serviceName;
    }

    private String buildServiceTopicWithID(String myClientID, String serviceName){
        return "mhub/"+ myClientID + "/service_topic/" + serviceName;
    }

    public void grantPermissionByServiceName(String clientID, String serviceName, String permission){
        try {
            File acl = new File(path,ACLFile);
            FileOutputStream fOut = new FileOutputStream(acl, true);
            String topic = buildServiceTopic(serviceName);



            StringBuilder rule = new StringBuilder();


            if(permission.equals("write")){
                rule.append(clientID).append(" ")
                        .append(topic.replace("+", clientID)).append(" ")
                        .append(permission).append("\n");
            }else{
                rule.append(clientID).append(" ")
                        .append(topic).append(" ")
                        .append(permission).append("\n");
            }

            fOut.write(rule.toString().getBytes());
            fOut.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    public void revokePermissionByServiceName(String clientID, String serviceName, String permission){

        StringBuilder newRules = new StringBuilder();
        StringBuilder ruleToEraseBuilder = new StringBuilder();

        List<String> rules = getCDDLRules();
        String topic = buildServiceTopic(serviceName);
        String ruleToErase;
        if(permission.equals("write")){
            ruleToErase = ruleToEraseBuilder.append(clientID).append(" ").append(topic.replace("+",clientID)).append(" ").append(permission).toString();

        }else{
            ruleToErase = ruleToEraseBuilder.append(clientID).append(" ").append(topic).append(" ").append(permission).toString();
        }
        for(String rule : rules){
            if (!ruleToErase.equals(rule)) {
                newRules.append(rule).append("\n");
            }
        }
        try {
            File file = new File(path, ACLFile);
            FileOutputStream fOut = new FileOutputStream(file, true);
            fOut.write(newRules.toString().getBytes());
            fOut.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void revokePermissionByCDDLTopic(String clientID, String topic_name, String permission){

        StringBuilder newRules = new StringBuilder();
        StringBuilder ruleToEraseBuilder = new StringBuilder();

        List<String> rules = getCDDLRules();
        String topic = buildTopic(topic_name);
        String ruleToErase;

        if(topic.equals("all_topics")){
            ruleToErase = ruleToEraseBuilder.append(clientID).append(" ").append(topic).append(" ").append(permission).toString();

        }else{
            if(permission.equals("write")){
                ruleToErase = ruleToEraseBuilder.append(clientID).append(" ").append(topic.replace("+",clientID)).append(" ").append(permission).toString();

            }else{
                ruleToErase = ruleToEraseBuilder.append(clientID).append(" ").append(topic).append(" ").append(permission).toString();
            }
        }

        for(String rule : rules){
            if (!ruleToErase.equals(rule)) {
                newRules.append(rule).append("\n");
            }
        }
        try {
            File file = new File(path, ACLFile);
            FileOutputStream fOut = new FileOutputStream(file);
            fOut.write(newRules.toString().getBytes());
            fOut.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public void revokePermissionByCustomTopic(String clientID, String topic, String permission){

        StringBuilder newRules = new StringBuilder();
        StringBuilder ruleToEraseBuilder = new StringBuilder();

        List<String> rules = getCDDLRules();

        String ruleToErase = ruleToEraseBuilder.append(clientID).append(" ").append(topic).append(" ").append(permission).toString();

        for(String rule : rules){
            if (!ruleToErase.equals(rule)) {
                newRules.append(rule).append("\n");
            }
        }
        try {
            File file = new File(path, ACLFile);
            FileOutputStream fOut = new FileOutputStream(file);
            fOut.write(newRules.toString().getBytes());
            fOut.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }




}
