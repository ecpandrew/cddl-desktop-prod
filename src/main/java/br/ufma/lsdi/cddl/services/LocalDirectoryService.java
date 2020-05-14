package br.ufma.lsdi.cddl.services;

/**
 * Created by lcmuniz on 05/03/17.
 */
public class LocalDirectoryService  {

    private static final String TAG = LocalDirectoryService.class.getSimpleName();

    private LocalDirectoryImpl localDirectory;

    public int startService() {

        localDirectory = new LocalDirectoryImpl();

        return 0;

    }

    public void stopService() {
        localDirectory.close();
    }

}
