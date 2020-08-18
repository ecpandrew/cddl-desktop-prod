package br.ufma.lsdi.security.helpers;


import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class TxtFileHelper {


    public static boolean fileExists(String p, String fileName){
        String path = p + "/" + fileName;
        File file = new File(path);
        return file.exists();
    }

    public static void eraseTxtFileContent(String p, String fileName){
        String path = p + "/" + fileName;
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(path);
            pw.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void createAndSaveKeystoreInTxtFile(String p, String keyStoreType, char[] password, String keystoreFileInternal){
        try {
            Log.debug("debug ","Empty Keystore created using PKCS12 type.");
            KeyStore ks = KeyStore.getInstance(keyStoreType);

            ks.load(null, password);
//            FileOutputStream outputStream = context.openFileOutput(keystoreFileInternal, Context.MODE_PRIVATE);

            String path = p + "/" + keystoreFileInternal;
            File file = new File(path);
            FileOutputStream outputStream = new FileOutputStream(file);

            ks.store(outputStream, password);
            Log.debug("debug","Keystore Initialized succesfully!!!!");

            outputStream.close();

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

    }


    public static void createACLFile(String p, String fileName){
        try {

            String path = p + "/" + fileName;
            File file = new File(path);
            FileOutputStream outputStream = new FileOutputStream(file);

            outputStream.close();
            Log.debug("debug","ACL File Initialized succesfully!!!!");

        } catch (IOException e) {
            e.printStackTrace();
        }

    }





    public static void saveCSRInTxtFile(String p, String csrFileInternal, byte[] csr){

        eraseTxtFileContent(p, csrFileInternal);

        File file_csr;
//        File file_csr_external;
        FileOutputStream csrOutputStream;

        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        try {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr));
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String csrPEM = writer.toString();
        try
        {
            file_csr = new File(p,csrFileInternal);
            csrOutputStream = new FileOutputStream(file_csr);
            csrOutputStream.write(csrPEM.getBytes());
            csrOutputStream.close();
//
//            file_csr_external = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), csrFileInternal);
//
//
//            csrOutputStream = new FileOutputStream(file_csr_external, false);
//            csrOutputStream.write(csrPEM.getBytes());
//            csrOutputStream.close();
//
//            Log.debug("csr", "saveCSRInTxtFile: csr exported to downloads");
//
//            MediaScannerConnection.scanFile(context, new String[]{file_csr_external.getAbsolutePath()}, null, null);

        }
        catch (IOException e)
        {
            e.printStackTrace();
        }


    }





}
