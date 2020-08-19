package br.ufma.lsdi.cddl;

import br.ufma.lsdi.cddl.network.MicroBroker;
import br.ufma.lsdi.cddl.pubsub.CDDLFilterImpl;
import br.ufma.lsdi.cddl.qos.AbstractQoS;
import br.ufma.lsdi.cddl.services.CommandService;
import br.ufma.lsdi.cddl.services.LocalDirectory;
import br.ufma.lsdi.cddl.services.LocalDirectoryService;
import br.ufma.lsdi.cddl.services.QoCEvaluatorService;
import br.ufma.lsdi.cddl.util.Asserts;
import br.ufma.lsdi.cddl.util.CDDLEventBus;
import lombok.val;

/**
 * Created by lcmuniz on 05/05/17.
 */
public final class CDDL {

    private static final CDDL instance = new CDDL();

    private boolean servicesStarted = false;

    private Connection connection;
    private CommandService cs;
    private QoCEvaluatorService qoc;
    private LocalDirectoryService ld;

    /**
     * Gets the CDDL instance.
     * @return the CDDL instance.
     */
    public static CDDL getInstance() {
        return instance;
    }

    /**
     * Starts the CDDL services.
     */
    public synchronized void startService() {

        Asserts.assertNotNull(connection, "Connection must be set in CDDL before calling startServices.");

        if (!servicesStarted) {

            cs = new CommandService();
            cs.startService();

            qoc = new QoCEvaluatorService();
            qoc.startService();

            ld = new LocalDirectoryService();
            ld.startService();

            servicesStarted = true;

        }

    }

    /**
     * Stops the CDDL services.
     */
    public synchronized void stopService() {

        if (servicesStarted) {

            ld.stopService();

            qoc.stopService();

            cs.stopService();

            servicesStarted = false;

        }

    }

    public static String startMicroBroker(String host, String port, String webSocketPort, String passwordFile) {
        return MicroBroker.getInstance().start(host, port, webSocketPort, passwordFile);
    }

    public static String startSecureMicroBroker(String pwd, boolean requireClientCertificate) {
        return MicroBroker.getInstance().secureStart(pwd, requireClientCertificate);
    }

    /**
     * Starts the MQTT microbroker
     */
    public static String startMicroBroker() {
        return MicroBroker.getInstance().start();
    }

    /**
     * Stops the MQTT microbroker
     */
    public static void stopMicroBroker() {
        MicroBroker.getInstance().stop();
    }

    /**
     * Sets the connection to be used for the CDDL instance.
     * @param connection The connection to be used for the CDDL instance.
     */
    public void setConnection(Connection connection) {
        this.connection = connection;
    }

    /**
     * Gets the connection used by the CDDL instance.
     * @return the connection used by the CDDL instance.
     */
    public Connection getConnection() {
        return connection;
    }


    public void setFilter(String eplFilter) {
        val cddlFilter = new CDDLFilterImpl(eplFilter);
        CDDLEventBus.getDefault().post(cddlFilter);
    }

    public void clearFilter() {
        val cddlFilter = new CDDLFilterImpl("");
        CDDLEventBus.getDefault().post(cddlFilter);
    }

    public void setQoS(AbstractQoS qos) {
        CDDLEventBus.getDefault().postSticky(qos);
    }

}
