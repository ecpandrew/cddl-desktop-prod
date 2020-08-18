package io.moquette.broker.security;

public class CDDLAuthorization {

    protected final String clientID;

    protected final String topic;
    protected final String permission;

    /**
     * Access rights
     */


    CDDLAuthorization(String clientID, String topic, String permission) {
        this.clientID = clientID;
        this.topic = topic;
        this.permission = permission;
    }


    boolean grantRead(String desiredID, String desiredTopic) {
        return clientID.equals(desiredID) && (topic.equals(desiredTopic) || topic.equals("all_topics")) && (permission.equals("read") || permission.equals("readwrite"));
    }

    boolean grantWrite(String desiredID, String desiredTopic) {
        return clientID.equals(desiredID) && (topic.equals(desiredTopic) || topic.equals("all_topics")) && (permission.equals("write") || permission.equals("readwrite"));
    }



    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        CDDLAuthorization that = (CDDLAuthorization) o;

        if (!permission.equals(that.permission))
            return false;
        if (!topic.equals(that.topic))
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = topic.hashCode();
        result = 31 * result + permission.hashCode();
        return result;
    }
}