package br.ufma.lsdi.cddl.services;

/**
 * Created by lcmuniz on 05/03/17.
 */
public class CommandService  {

    private static final String TAG = CommandService.class.getSimpleName();

    private CommandServiceImpl command;

    public int startService() {

        command = new CommandServiceImpl();

        return 0;
    }

    public void stopService() {
        command.close();
    }

}
