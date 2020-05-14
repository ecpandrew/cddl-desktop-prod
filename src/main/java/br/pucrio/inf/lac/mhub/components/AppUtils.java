package br.pucrio.inf.lac.mhub.components;

import org.json.JSONArray;

import java.io.File;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The utilities used by the application.
 *
 * @author Luis Talavera
 */
public class AppUtils {
    /**
     * DEBUG
     */
    private static final String TAG = AppUtils.class.getSimpleName();

    /**
     * Property separator, used to separate the route tag
     */
    private static final String PROP_SEP = "\\|";

    /**
     * It checks if is a valid IP address.
     *
     * @param s The IP address string.
     * @return true  If the pattern is valid.
     * false If the pattern fails.
     */
    public static Boolean isValidIp(String s) {
        String PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
        Pattern pattern = Pattern.compile(PATTERN);
        Matcher matcher = pattern.matcher(s);
        return matcher.matches();
    }

    /**
     * It checks if is a valid port range between 1 and 65535.
     *
     * @param s The gateway port string.
     * @return true  A valid port.
     * false A not valid port.
     */
    public static Boolean isValidPort(String s) {
        if (!isNumber(s))
            return false;
        else {
            int port = Integer.parseInt(s);
            if (port >= 1 && port <= 65535)
                return true;
        }
        return false;
    }

    /**
     * A simple check to see if a string is a valid number before inserting
     * into the shared preferences.
     *
     * @param s The number to be checked.
     * @return true  It is a number.
     * false It is not a number.
     */
    public static Boolean isNumber(String s) {
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return false;
        }
        return true;
    }

    /**
     * A simple check to see if a string is a valid double before inserting
     * into the shared preferences.
     *
     * @param s The number to be checked.
     * @return true  It is a number.
     * false It is not a number.
     */
    public static Boolean isDouble(String s) {
        try {
            Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return false;
        }
        return true;
    }

    /**
     * It generates a random UUID for the Android device.
     *
     * @return It returns the generated UUID.
     */
    private static UUID generateUuid() {
        return UUID.randomUUID();
    }

    /**
     * Look for the service tag in the property
     *
     * @param serviceName The service name to check
     * @param property    The allowed services
     * @return If the service is allowed
     */
    public static boolean isInRoute(String serviceName, String property) {
        String[] parts = property.split(PROP_SEP);

        for (String service : parts) {
            if (service.equals(serviceName))
                return true;
        }

        return false;
    }
    /**
     * Deletes a directory
     *
     * @param dir The directory to delete
     * @return If it was deleted successfully
     */
    public static boolean deleteDir(File dir) {
        if (dir != null && dir.isDirectory()) {
            String[] children = dir.list();
            for (String aChildren : children) {
                boolean success = deleteDir(new File(dir, aChildren));
                if (!success)
                    return false;
            }

            return dir.delete();
        }
        return false;
    }

    /**
     * Gets an element in its String representation
     *
     * @param obj The object to be transformed
     * @return The String representation
     */
    public static String valueOf(Object obj) {
        return (obj == null) ? "null" : obj.toString();
    }

    /**
     * Transforms a Map to a JSONArray structure
     *
     * @param data the Map with the data
     * @return a JSONArray with the values of the data (key - value)
     * @throws NullPointerException
     */
    public static JSONArray mapToJSONArray(Map<?, ?> data) throws NullPointerException {
        JSONArray properties = new JSONArray();
        for (Map.Entry<?, ?> entry : data.entrySet()) {
            JSONArray property = new JSONArray();

            String key = (String) entry.getKey();
            Object value = entry.getValue();

            if (key == null) throw new NullPointerException("key == null");

            property.put(key);
            if (value instanceof String)
                property.put(value);
            else if (value instanceof Class)
                property.put(((Class) value).getName());

            properties.put(property);
        }
        return properties;
    }

    /**
     * Gyroscope, Magnetometer, Barometer, IR temperature all store 16 bit two's complement values in the awkward format LSB MSB, which cannot be directly parsed
     * as getIntValue(FORMAT_SINT16, offset) because the bytes are stored in the "wrong" direction.
     * <p>
     * This function extracts these 16 bit two's complement values.
     **/
    public static Integer shortSignedAtOffset(byte[] c, int offset) {
        Integer lowerByte = (int) c[offset] & 0xFF;
        Integer upperByte = (int) c[offset + 1]; // // Interpret MSB as signed
        return (upperByte << 8) + lowerByte;
    }

    public static Integer shortUnsignedAtOffset(byte[] c, int offset) {
        Integer lowerByte = (int) c[offset] & 0xFF;
        Integer upperByte = (int) c[offset + 1] & 0xFF; // // Interpret MSB as signed
        return (upperByte << 8) + lowerByte;
    }

    /**
     * Transforms bytes to String
     *
     * @param data bytes
     * @return String
     */
    public static String bytesToHex(byte[] data) {
        if (data == null)
            return null;

        String str = "";
        for (byte aData : data) {
            if ((aData & 0xFF) < 16)
                str = str + "0" + Integer.toHexString(aData & 0xFF);
            else
                str = str + Integer.toHexString(aData & 0xFF);
        }
        return str;
    }

    /**
     * Logger for the service, depending on the flag DEBUG
     *
     * @param type The char type of the log
     * @param TAG  The String used to know to which class the log belongs
     * @param text The String to output on the log
     */
    public static void logger(char type, final String TAG, final String text) {
        if (text == null) {
            System.out.println("MHub " + TAG + " " + "NULL Message");
            return;
        }

        if (AppConfig.DEBUG) {
            switch (type) {
                case 'i': // Information
                    System.out.println("MHub " + TAG + " " + text);
                    break;

                case 'w': // Warning
                    System.out.println("MHub " + TAG + " " + text);
                    break;

                case 'e': // Error
                    System.out.println("MHub " + TAG + " " + text);
                    break;

                case 'd': // Debug
                    System.out.println("MHub " + TAG + " " + text);
                    break;

                default:
                    System.out.println("MHub " + TAG + " " + text);
                    break;
            }
        }
    }
}
