package org.bitcoinj.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.slf4j.LoggerFactory;

/**
 * New Properties file loader.
 *
 * @author v
 */
public class PropertiesReader {

	private static final org.slf4j.Logger log = LoggerFactory.getLogger(PropertiesReader.class);
    private static final String settings_loc = "setup.properties";
    private static final Properties props = new Properties();

    static {
        try (FileInputStream fis = new FileInputStream(settings_loc)) {
            props.load(fis);
        } catch (FileNotFoundException ex) {
            log.error("Properties file not found, exiting ", ex);
            System.exit(-1);
        } catch (IOException ex) {
            log.error("IOException while reading properties, exiting", ex);
            System.exit(-1);
        }
    }

    /**
     * Get the enabled protocols to be used with a
     * {@link javax.net.ssl.SSLEngine}.
     *
     * @return the enabled protocols to be used with a
     * {@link javax.net.ssl.SSLEngine}.
     */
    public static String[] getProtocols() {
        String[] ret = getPropAsStrArr("secure.protocols");
        return ret;
    }

    /**
     * Get the enabled cipher suites to be used with a
     * {@link javax.net.ssl.SSLEngine}.
     *
     * @return the enabled cipher suites to be used with a
     * {@link javax.net.ssl.SSLEngine}.
     */
    public static String[] getCipherSuites() {
        String[] ret = getPropAsStrArr("secure.cipherSuites");

        return ret;
    }

    public static boolean getTCPNoDelay() {
        return getPropAsBool("socket.tcp_nodelay");
    }


    /**
     * Return a property as a String array.
     *
     * @param key The key used to retrieve the property
     * @return the returned String array
     */
    private static String[] getPropAsStrArr(String key) {
        String str = getProp(key);
        String[] ret = str.split(" ");
        return ret;
    }

    /**
     * Return a property as a long. An error is thrown if the number is smaller
     * than zero.
     *
     * @param key The key used to retrieve the property
     * @return the returned long
     */
    private static long getPropAsLong(String key) {
        String str = getProp(key);
        long l = -1;
        try {
            l = Long.parseLong(str);
        } catch (NumberFormatException nfe) {
            log.error(key + " value is invalid, shutting down", nfe);
            System.exit(-1);
        }
        return l;
    }

    /**
     * Return a property as an int. An error is thrown if the number is smaller
     * than zero.
     *
     * @param key The key used to retrieve the property
     * @return the returned int
     */
    private static int getPropAsInt(String key) {
        String str = getProp(key);
        int i = -1;
        try {
            i = Integer.parseInt(str);
        } catch (NumberFormatException nfe) {
            log.error(key + " value is invalid, shutting down", nfe);
            System.exit(-1);
        }
        return i;
    }

    /**
     * Return a property as a boolean. An error is thrown if the values are
     * anything other than "true" or "false".
     *
     * @param key The key used to retrieve the property
     * @return the returned boolean
     */
    private static boolean getPropAsBool(String key) {
        String str = getProp(key);
        if (!str.equals("true") && !str.equals("false")) {
            log.error("{0} value is invalid: {1}. Shutting down",
                    new Object[]{key, str});
            System.exit(-1);
        }
        return Boolean.parseBoolean(str);
    }

    /**
     * Get a property. An error is thrown if the value of the property is not
     * found or is empty.
     *
     * @param key The key used to retrieve the property
     * @return the associated property
     */
    private static String getProp(String key) {
        String str = props.getProperty(key);
        if (str == null || str.isEmpty()) {
            // Fail, these are essential properties
            log.error(key+ " value not found, shutting down.");
            System.exit(-1);
        }
        return str;
    }

    private PropertiesReader() {
    	
    }
    
    //public static void main(String[] args) {
    //PropertiesReader.getSoSndBuf();
    //String[] s = PropertiesReader.getPropAsStrArr("secure.cipherSuites");
    //for (int i = 0; i < s.length; i++) {
    //    System.out.println(s[i]);
    //}
    //}
}
