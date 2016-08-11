package org.bitcoinj.net;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import org.bitcoinj.utils.PropertiesReader;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.AbstractExecutionThreadService;


public abstract class AbstractSecureNio extends AbstractExecutionThreadService {

	private static final org.slf4j.Logger log = LoggerFactory.getLogger(AbstractSecureNio.class);
	 
	protected InetSocketAddress bindAddress;
	
	protected final boolean usingSSL;
	protected final boolean isClient;
	protected final boolean needClientAuth;
	protected SSLContext context = null;
	
	protected String[] protocols;
	protected String[] cipherSuits;

	public AbstractSecureNio(InetSocketAddress bindAddress, boolean usingSSL,
            boolean isClient, boolean needClientAuth) {
        this.bindAddress = bindAddress;
        this.usingSSL = usingSSL;
        this.isClient = isClient;
        this.needClientAuth = needClientAuth;
        log.info("Using ssl: "+ usingSSL+" isServer: "+ !isClient);
    }
    
	protected AbstractSecureNio(boolean usingSSL, boolean isClient, boolean needClientAuth) {
		this.usingSSL = usingSSL;
        this.isClient = isClient;
        this.needClientAuth = needClientAuth;
        log.info("Using ssl: "+ usingSSL+" isClient: "+ isClient);
	}
	
	 
    public void setupSSL(String trustStoreLoc, String keyStoreLoc,
            char[] tsPassPhrase, char[] ksPassPhrase) {
        if (!usingSSL) {
            log.warn("Trying to set SSL parameters with a " + "non-SSL/TLS "+(isClient ? "client" : "server") + ". SSL/TLS was NOT set or initialized.");
            return;
        }

        protocols = PropertiesReader.getProtocols();
        cipherSuits = PropertiesReader.getCipherSuites();
                
        TrustManagerFactory tmf = null;
        KeyManagerFactory kmf = null;
        KeyStore ks = null;
        FileInputStream fis = null;

        if (isClient || (!isClient && needClientAuth)) {
            // Need to initialize truststores
            try {
                tmf = TrustManagerFactory.getInstance("SunX509");
                ks = KeyStore.getInstance("JKS");
                fis = new FileInputStream(trustStoreLoc);
                ks.load(fis, tsPassPhrase);
                tmf.init(ks);
            } catch (NoSuchAlgorithmException nsae) {
                nsae.printStackTrace();
                // tmf
            } catch (KeyStoreException kse) {
                kse.printStackTrace();
                // ks, tmf.init()
            } catch (FileNotFoundException fnfe) {
                fnfe.printStackTrace();
                // fis
            } catch (IOException ioe) {
                ioe.printStackTrace();
                // ks.load()
            } catch (CertificateException ce) {
                ce.printStackTrace();
                // ks.load()
            } finally {
                try {
                    fis.close();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                    // fis.close();
                }
            }
        }

        if (!isClient || (isClient && needClientAuth)) {
            // Need to initialize keystores
            try {
                kmf = KeyManagerFactory.getInstance("SunX509");
                ks = KeyStore.getInstance("JKS");
                fis = new FileInputStream(keyStoreLoc);
                ks.load(fis, ksPassPhrase);
                kmf.init(ks, ksPassPhrase);
            } catch (NoSuchAlgorithmException nsae) {
                nsae.printStackTrace();
                // kmf
            } catch (KeyStoreException kse) {
                kse.printStackTrace();
                // kmf.init()
            } catch (UnrecoverableKeyException uke) {
                uke.printStackTrace();
                // kmf.init()
            } catch (FileNotFoundException fnfe) {
                fnfe.printStackTrace();
                // fis, fis.close()
            } catch (IOException ioe) {
                ioe.printStackTrace();
                // ks.load()
            } catch (CertificateException ce) {
                ce.printStackTrace();
                // ks.load()
            } finally {
                try {
                    fis.close();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                    // fis.close();
                }
            }
        }
        // Finally, initialize the context
        try {
            context = SSLContext.getInstance("TLS");//.getDefault();//getInstance("TLS");
            
            if (kmf == null) {
                context.init(null, tmf.getTrustManagers(), null);
            } else if (tmf == null) {
                context.init(kmf.getKeyManagers(), null, null);
            } else {
                context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            }
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            // context
        } catch (KeyManagementException kme) {
            kme.printStackTrace();
            // context.init()
        }
        log.info("-----------------Set up ssl: "+ usingSSL+" isServer: "+ !isClient);
    }
    
	/**
     * Sets up the underlying SSLEngine to be used with a
     * securenio.socket.secure.SecureSocket implementation.
     * The SSLEngine is initialized based on whether this instance is a server
     * or a client, whether we need clientAuth or not, and based on the provided
     * protocols and cipher suites provided in {@link
     * #setupSSL(String trustStoreLoc, String keyStoreLoc, char[] tsPassPhrase,
     * char[] ksPassPhrase, String protocolsLoc, String cipherSuitesLoc)}. The
     * peerHost and peerPort parameters are passed as hints to the
     * {@link SSLEngine} for engine re-usage purposes but can also be null.
     *
     * @param peerHost The peer host of the socket
     * @param peerPort The peer port of the socket
     * @return An initialized and configured SSLEngine ready to be used
     */
    protected SSLEngine setupEngine(String peerHost, int peerPort) {
        SSLEngine engine = context.createSSLEngine(peerHost, peerPort);
        engine.setUseClientMode(isClient);
        engine.setNeedClientAuth(needClientAuth);
       
        try {
			engine.beginHandshake();
		} catch (SSLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        // Setup protocols and suites
        try {
            engine.setEnabledProtocols(protocols);
        } catch (IllegalArgumentException iae) {
            log.warn("Provided protocols invalid, using default ", iae);
        }

        try {
            engine.setEnabledCipherSuites(cipherSuits);
        } catch (IllegalArgumentException iae) {
            log.warn("Provided cipher suites invalid, using default", iae);
        }
        log.info("-----------------Set up Engine: {}: {}", peerHost, peerPort);
        log.info("-----------------Engine UseClientMode: {}", engine.getUseClientMode());
        log.info("-----------------Supported protocols : "+ Arrays.asList(engine.getSupportedProtocols()));
        log.warn("-----------------Enabled protocols : "+ Arrays.asList(engine.getEnabledProtocols()));
        log.info("-----------------Supported cipher suites : "+ Arrays.asList(engine.getSupportedCipherSuites()));
        log.warn("-----------------Enabled cipher suites : "+ Arrays.asList(engine.getEnabledCipherSuites()));
//        if (usingSSL) {
//            String keyStoreLoc = "serverkey.jks";
//            char[] ksPassPhrase = "123456".toCharArray();
//            String trustStoreLoc = "servertrust.jks";
//            char[] tsPassPhrase = "123456".toCharArray();
//            if (!needClientAuth) {
//              if(isClient){//client
//            	  keyStoreLoc = null;
//            	  ksPassPhrase = null;
//              } else{//server
//                  trustStoreLoc = null;
//                  tsPassPhrase = null;
//              }
//            }
//            setupSSL(trustStoreLoc, keyStoreLoc, tsPassPhrase, ksPassPhrase, "protocols", "cipherSuites");
//        }
        
        return engine;
    }
}
