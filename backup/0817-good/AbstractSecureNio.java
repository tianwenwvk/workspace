package org.bitcoinj.net;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import org.bitcoinj.utils.PropertiesReader;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.AbstractExecutionThreadService;


public abstract class AbstractSecureNio extends AbstractExecutionThreadService {

	private static final org.slf4j.Logger log = LoggerFactory.getLogger(AbstractSecureNio.class);
	
	public static boolean usingSSL = PropertiesReader.getUsingSSL();
	protected static String[] protocols = PropertiesReader.getProtocols();
	protected static String[] cipherSuits = PropertiesReader.getCipherSuites();
	
	private String trustStoreLoc = PropertiesReader.getTrustStoreLoc();
	private char[] tsPassPhrase = PropertiesReader.getTrustStorePassPhrase().toCharArray();
	private String keyStoreLoc = PropertiesReader.getKeyStoreLoc();
	private char[] ksPassPhrase = PropertiesReader.getKeyStorePassPhrase().toCharArray();
	
	protected final boolean isClient;
	protected boolean needClientAuth;
	protected SSLContext context;
	//protected SSLEngine engine;
	
	
	public AbstractSecureNio(boolean isClient) {
        this.isClient = isClient;
        if(usingSSL){
	        this.needClientAuth = true;//if turn on usingSSL, it will always set NeedClientAuth=true
	        this.context = setupSSLContext();
	        //this.engine = setupEngine();
        }
        log.info("Set up ssl context! UsingSSL: "+ usingSSL+" isClient: "+ isClient);
	}
		

	private SSLContext setupSSLContext() {
        
		if (!usingSSL) {
			log.warn("Trying to set SSL parameters with a " + "non-SSL/TLS " + (isClient ? "client" : "server")
					+ ". SSL/TLS was NOT set or initialized.");
			return null;
		}

	    TrustManagerFactory tmf = null;
        KeyManagerFactory kmf = null;
        KeyStore ks = null;
        FileInputStream fis = null;
       
		/*** Need to initialize truststores ***/
		try {
			tmf = TrustManagerFactory.getInstance("SunX509");
			ks = KeyStore.getInstance("JKS");
			fis = new FileInputStream(trustStoreLoc);
			ks.load(fis, tsPassPhrase);
			tmf.init(ks);
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException kse) {
			kse.printStackTrace();
		} catch (FileNotFoundException fnfe) {
			fnfe.printStackTrace();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} finally {
			try {
				fis.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		}

		/*** initialize keystores ***/
		try {
			kmf = KeyManagerFactory.getInstance("SunX509");
			ks = KeyStore.getInstance("JKS");
			fis = new FileInputStream(keyStoreLoc);
			ks.load(fis, ksPassPhrase);
			kmf.init(ks, ksPassPhrase);
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException ke) {
			ke.printStackTrace();
		} catch (FileNotFoundException fnfe) {
			fnfe.printStackTrace();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} finally {
			try {
				fis.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		}

		/*** initialize the context ***/
		SSLContext context = null;
		try {
			context = SSLContext.getInstance("TLS");

			if (kmf == null) {
				context.init(null, tmf.getTrustManagers(), null);
			} else if (tmf == null) {
				context.init(kmf.getKeyManagers(), null, null);
			} else {
				context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			}
		} catch (NoSuchAlgorithmException |KeyManagementException cte) {
			cte.printStackTrace();
		}
       
       log.info("-----------------Set up ssl: "+ usingSSL+" isClient: "+ isClient);
       return context;
   }
   
	protected SSLEngine setupEngine() {

		SSLEngine engine = context.createSSLEngine();
		engine.setUseClientMode(isClient);
		engine.setNeedClientAuth(needClientAuth);

		/*** Setup protocols and suites ***/
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
		log.info("-----------------Set up Engine: UseClientMode: {}", engine.getUseClientMode());

		return engine;
	}
	
	/**
    * Sets up the underlying SSLEngine to be used.
    * The SSLEngine is initialized based on the provided protocols and cipher suites provided in 
    * {@link#setupSSL(String trustStoreLoc, String keyStoreLoc, char[] tsPassPhrase,
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
      
       /*** Setup protocols and suites ***/
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
       log.info("-----------------Set up Engine: {}: {}  UseClientMode: {}", peerHost, peerPort, engine.getUseClientMode());
       
       return engine;
   }
   
	
    
    
}
