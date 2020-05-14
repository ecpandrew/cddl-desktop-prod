package br.ufma.lsdi.cddl.services;

/**
 * Created by lcmuniz on 05/03/17.
 */
public class QoCEvaluatorService {

    private static final String TAG = QoCEvaluatorService.class.getSimpleName();

    private QoCEvaluatorImpl qocEvaluator;

    public int startService() {

        qocEvaluator = new QoCEvaluatorImpl();

        return 0;

    }

    public void stopService() {
        qocEvaluator.close();
    }

}
