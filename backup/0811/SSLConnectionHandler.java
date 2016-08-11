package org.bitcoinj.net;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import java.io.IOException;
import java.net.SocketException;
import java.nio.Buffer;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.bitcoinj.core.Message;
import org.bitcoinj.utils.Threading;
import org.slf4j.LoggerFactory;

import com.google.common.base.Throwables;

public class SSLConnectionHandler implements MessageWriteTarget {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(SSLConnectionHandler.class);

//    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
//    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    private static final int OUTBOUND_BUFFER_BYTE_COUNT = Message.MAX_SIZE + 24; // 24 byte message header

    // We lock when touching local flags and when writing data, but NEVER when calling any methods which leave this
    // class into non-Java classes.
    private final ReentrantLock lock = Threading.lock("nioSSLConnectionHandler");
    
    @GuardedBy("lock") private final SocketChannel channel;
    @GuardedBy("lock") private final SelectionKey key;
    @GuardedBy("lock") StreamConnection connection;
    @GuardedBy("lock") private boolean closeCalled = false;

    @GuardedBy("lock") private long bytesToWriteRemaining = 0;//decryptedOut
    @GuardedBy("lock") private final LinkedList<ByteBuffer> bytesToWrite = new LinkedList<ByteBuffer>();

//    @GuardedBy("lock") private final ByteBuffer encryptIn;
//    @GuardedBy("lock") private final ByteBuffer encryptedOut;
//    @GuardedBy("lock") private final ByteBuffer decryptedIn;
    private ByteBuffer encryptIn;
    private ByteBuffer encryptedOut;
    private ByteBuffer decryptedIn;
    private ByteBuffer decryptedOut;
    protected static ByteBuffer emptybuffer ;
    protected int bufferallocations = 0;
    private volatile boolean handshakePending = true;
    
    private Set<SSLConnectionHandler> connectedHandlers;
    private SSLEngineResult sslEngineResult;
//    private SSLEngineResult readEngineResult;
//    private SSLEngineResult writeEngineResult;
    private SSLEngine engine;
    
    public SSLConnectionHandler(StreamConnectionFactory connectionFactory, SelectionKey key, SSLEngine engine) throws IOException {
        this(connectionFactory.getNewConnection(((SocketChannel) key.channel()).socket().getInetAddress(), ((SocketChannel) key.channel()).socket().getPort()), key, engine);
        if (connection == null)
            throw new IOException("Parser factory.getNewConnection returned null");
    }

    private SSLConnectionHandler(@Nullable StreamConnection connection, SelectionKey key, SSLEngine engine) {
        this.key = key;
        this.channel = checkNotNull(((SocketChannel)key.channel()));
        
        if (connection == null || engine == null) {
            encryptIn = null;
            encryptedOut = null;
            decryptedIn = null;
            return;
        }
        this.connection = connection;
        //encryptIn = ByteBuffer.allocateDirect(Math.min(Math.max(engine.getSession().getPacketBufferSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        connection.setWriteTarget(this); // May callback into us (eg closeConnection() now)
        connectedHandlers = null;
       
        this.engine = engine;
        int appBufSize = engine.getSession().getApplicationBufferSize();
        int netBufSize = engine.getSession().getPacketBufferSize();
//        encryptIn = ByteBuffer.allocateDirect(Math.min(Math.max(netBufSize, BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
//        encryptedOut = ByteBuffer.allocateDirect(Math.min(Math.max(netBufSize, BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
//        decryptedIn = ByteBuffer.allocateDirect(Math.min(Math.max(appBufSize, BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));

        encryptIn = ByteBuffer.allocate(netBufSize);
        encryptedOut = ByteBuffer.allocate(netBufSize);
        decryptedIn = ByteBuffer.allocate(appBufSize);
        decryptedOut = ByteBuffer.allocate(appBufSize);
       // readEngineResult = writeEngineResult = new SSLEngineResult( Status.BUFFER_UNDERFLOW, engine.getHandshakeStatus(), 0, 0 ); // init to prevent NPEs
        
        char ch = 'v';
        emptybuffer = ByteBuffer.allocate(4);
		emptybuffer.putChar(ch );
    }

    public SSLConnectionHandler(StreamConnection connection, SelectionKey key, Set<SSLConnectionHandler> connectedHandlers,SSLEngine engine) {
        this(checkNotNull(connection), key, engine);

        // closeConnection() may have already happened because we invoked the other c'tor above, which called
        // connection.setWriteTarget which might have re-entered already. In this case we shouldn't add ourselves
        // to the connectedHandlers set.
        lock.lock();
        try {
            this.connectedHandlers = connectedHandlers;
            if (!closeCalled)
                checkState(this.connectedHandlers.add(this));
        } finally {
            lock.unlock();
        }
    }

    @GuardedBy("lock")
    private void setWriteOps() {
        // Make sure we are registered to get updated when writing is available again
        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
        // Refresh the selector to make sure it gets the new interestOps
        key.selector().wakeup();
    }

    // Tries to write any outstanding write bytes, runs in any thread (possibly unlocked)
//    private void tryWriteBytes() throws IOException {
//        lock.lock();
//        try {
////        	if( !isHandShakeComplete() ) {
////    			processHandshake();
////    			return ;
////    		}
//        	log.info("----------tryWriteBytes : start");
//            // Iterate through the outbound ByteBuff queue, pushing as much as possible into the OS' network buffer.
//            Iterator<ByteBuffer> bytesIterator = bytesToWrite.iterator();
//            while (bytesIterator.hasNext()) {
//                ByteBuffer buff = bytesIterator.next();
//                encryptedOut.compact();
//                sslEngineResult = engine.wrap(buff, encryptedOut);
//                encryptedOut.flip();
////                if (writeEngineResult.getStatus() == SSLEngineResult.Status.CLOSED) {
////                   // throw new Exception("Connection is closed");
////                	break;
////                }
//                bytesToWriteRemaining -= channel.write(encryptedOut);//TODO
//                log.info("----------tryWriteBytes : channel.write");
//                if (!buff.hasRemaining())
//                    bytesIterator.remove();
//                else {
//                    setWriteOps();
//                    break;
//                }
//                processHandshake();
//                
//            }
//            // If we are done writing, clear the OP_WRITE interestOps
//            if (bytesToWrite.isEmpty())
//                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
//            // Don't bother waking up the selector here, since we're just removing an op, not adding
//        } finally {
//            lock.unlock();
//        }
//    }

//    @Override
//    public void writeBytes(byte[] message) throws IOException {
//        boolean andUnlock = true;
//        lock.lock();
//        try {
//            // Network buffers are not unlimited (and are often smaller than some messages we may wish to send), and
//            // thus we have to buffer outbound messages sometimes. To do this, we use a queue of ByteBuffers and just
//            // append to it when we want to send a message. We then let tryWriteBytes() either send the message or
//            // register our SelectionKey to wakeup when we have free outbound buffer space available.
//
//            if (bytesToWriteRemaining + message.length > OUTBOUND_BUFFER_BYTE_COUNT)
//                throw new IOException("Outbound buffer overflowed");
//            
//			// Just dump the message onto the write buffer and call tryWriteBytes
//            // TODO: Kill the needless message duplication when the write completes right away
//            bytesToWrite.offer(ByteBuffer.wrap(Arrays.copyOf(message, message.length)));
////            encryptedOut.clear();
////            writeEngineResult = engine.wrap(ByteBuffer.wrap(Arrays.copyOf(message, message.length)), encryptedOut);
////            log.info("---------engine.wrap writeEngineResult: "+writeEngineResult+" status:"+writeEngineResult.getStatus()+" handshake:"+writeEngineResult.getHandshakeStatus());
////            bytesToWrite.offer(encryptedOut);
//            bytesToWriteRemaining += message.length;
//            setWriteOps();
//        } catch (IOException e) {
//            lock.unlock();
//            andUnlock = false;
//            log.warn("Error writing message to connection, closing connection", e);
//            closeConnection();
//            throw e;
//        } catch (CancelledKeyException e) {
//            lock.unlock();
//            andUnlock = false;
//            log.warn("Error writing message to connection, closing connection", e);
//            closeConnection();
//            throw new IOException(e);
//        } finally {
//            if (andUnlock)
//                lock.unlock();
//        }
//    }

    @Override
    public void writeBytes(byte[] message) throws IOException {
    	ByteBuffer buffer = ByteBuffer.wrap(Arrays.copyOf(message, message.length));
		// Make shallow copy, assumes the entire buffer needs to be written
        //System.out.println("buffer position" + buffer.position());
        //System.out.println("buffer capacity " + buffer.capacity());
        while (buffer .hasRemaining()) {
            decryptedOut.put(buffer.get());
        }
        //System.out.println("decryptedOut position " + decryptedOut.position());
        //System.out.println("decryptedOut capacity " + decryptedOut.capacity());

        int pos = decryptedOut.position();
        encryptedOut.clear();
        // Wrap the data to be written
        decryptedOut.flip();
        sslEngineResult = engine.wrap(decryptedOut, encryptedOut);
        decryptedOut.compact();
        // Process the engineResult.Status
        switch (sslEngineResult.getStatus()) {
            case BUFFER_UNDERFLOW:
                log.debug("{0} BUFFER_UNDERFLOW",
                        channel.socket().getRemoteSocketAddress());
                // This shouldn't happen as we only call write() when there is
                // data to be written, throw an exception that will be handled
                // in the application layer.
                throw new BufferUnderflowException();
            case BUFFER_OVERFLOW:
            	log.debug( "{0} BUFFER_OVERFLOW",
                        channel.socket().getRemoteSocketAddress());
                // This shouldn't happen if we flush data that has been wrapped
                // as we do in this implementation, throw an exception that will
                // be handled in the application layer.
                throw new BufferOverflowException();
            case CLOSED:
            	log.debug("{0} CLOSED",
                        channel.socket().getRemoteSocketAddress());
                // Trying to write on a closed SSLEngine, throw an exception
                // that will be handled in the application layer.
                throw new SSLException("SSLEngine is CLOSED");
            case OK:
            	log.debug("{0} OK",
                        channel.socket().getRemoteSocketAddress());
                // Everything is good, everything is fine.
                break;
        }
        // Process any pending handshake
        processHandshake();
        // Flush any pending data to the network
        flush();
        // return count of application bytes written.
        return ;
    }
    
    // May NOT be called with lock held
    @Override
    public void closeConnection() {
        checkState(!lock.isHeldByCurrentThread());
        try {
        	// Flush any pending encrypted output data
//        	if (key.isWritable())
//                tryWriteBytes();
            if (!engine.isOutboundDone()) {
                engine.closeOutbound();
                processHandshake();
                
            } else if (!engine.isInboundDone()) {
                // Closing inbound will throw an SSLException if we have not
                // received a close_notify.
                engine.closeInbound();
                // Process what we can before we close the channel.
                processHandshake();
            }
        } catch (IOException e) {
        	log.warn("Error handling closeConnection ",e);
		} finally {
            try {
	            channel.close();
	        } catch (IOException e) {
	            throw new RuntimeException(e);
	        }
        }
        connectionClosed();
    }

    private void connectionClosed() {
        boolean callClosed = false;
        lock.lock();
        try {
            callClosed = !closeCalled;
            closeCalled = true;
        } finally {
            lock.unlock();
        }
        if (callClosed) {
            checkState(connectedHandlers == null || connectedHandlers.remove(this));
            connection.connectionClosed();
        }
    }
       
    // Handle a SelectionKey which was selected
    // Runs unlocked as the caller is single-threaded (or if not, should enforce that handleKey is only called
    // atomically for a given SSLConnectionHandler)
    public static void handleKey(SelectionKey key) {
    	
        SSLConnectionHandler handler = ((SSLConnectionHandler)key.attachment());
        try {
        	 if (handler == null)
                 return;
             if( !handler.isHandShakeComplete() ) {
    			if( handler.isBlocking() ) {
    				while ( !handler.isHandShakeComplete() ) {
    					handler.processHandshake();
    				}
    			} else {
    				handler.processHandshake();
    				if( !handler.isHandShakeComplete() ) {
    					return ;
    				}else{
    					log.info("---------------- HandShakeCompleted! ------------");
    					//handler.connection.connectionOpened();
    				}
    			}
    		}
           if (!key.isValid()) {
                //handler.closeConnection(); // Key has been cancelled, make sure the socket gets closed
                return;
            }
            if (key.isReadable()) {
            	log.info("---------------- Process bytes read! ------------");
                // Do a socket read and invoke the connection's receiveBytes message
                int read = handler.channel.read(handler.encryptIn);
                if (read == 0)
                    return; // Was probably waiting on a write
                else if (read == -1) { // Socket was closed
                    key.cancel();
                    handler.closeConnection();
                    return;
                }
                handler.decryptedIn.clear();
                // "flip" the buffer - setting the limit to the current position and setting position to 0
                handler.encryptIn.flip();//handler.readEngineResult 
                handler.sslEngineResult = handler.engine.unwrap(handler.encryptIn, handler.decryptedIn);
                // Use connection.receiveBytes's return value as a check that it stopped reading at the right location
                //int bytesConsumed = checkNotNull(handler.connection).receiveBytes(handler.readBuff);
                int bytesConsumed = checkNotNull(handler.connection).receiveBytes(handler.decryptedIn);
                checkState(handler.encryptIn.position() == bytesConsumed);
                // Now drop the bytes which were read by compacting readBuff (resetting limit and keeping relative
                // position)
                handler.encryptIn.compact();
            }
//            if (key.isWritable())
//                handler.tryWriteBytes();
            handler.processHandshake();
        } catch (Exception e) {
            // This can happen eg if the channel closes while the thread is about to get killed
            // (ClosedByInterruptException), or if handler.connection.receiveBytes throws something
            Throwable t = Throwables.getRootCause(e);
            log.warn("Error handling SelectionKey: {}", t.getMessage() != null ? t.getMessage() : t.getClass().getName());
            log.error("Error handling SelectionKey: ", e);
            handler.closeConnection();
        }
    }
    
    public void initHandshake() {
        try {
			//engine.beginHandshake();
			processHandshake();
			log.info("----------processHandshake called ");
		} catch (SSLException e) {
			log.error("initHandshake failed - SSLException: ", e);
		} catch (IOException e) {
			log.error("initHandshake failed - IOException: ", e);
		}
        
    }

    @Override
    public boolean finishConnect(){
        boolean ret;
		try {
			ret = channel.finishConnect();
		
//	        if (ret) {// sanity check
//	            initHandshake();
//	        }
	        return ret;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			log.error("finishConnect ", e);
			return false;
		}
    }
 
   // @Override
    public void processHandshake() throws IOException {
        int count;
        SSLEngineResult.HandshakeStatus status;
        if (sslEngineResult == null) {
            status = engine.getHandshakeStatus();            
        } else {
            status = sslEngineResult.getHandshakeStatus();
        }
        // process the handshake status
        
        switch (status) {
            case NEED_TASK:
                log.debug("{0} NEED_TASK", channel.socket().getRemoteSocketAddress());
                // Run the delegated SSL/TLS tasks
                runDelegatedTasks();
                // Return as handshaking cannot continue
                //return;
                //break;
            case NEED_UNWRAP:
                log.debug("{0} NEED_UNWRAP", channel.socket().getRemoteSocketAddress());
                // Don’t read if inbound is already closed
                count = engine.isInboundDone() ? -1 : channel.read(encryptIn);
                log.debug("Read {0} bytes", count);
                encryptIn.flip();
                try {
                	sslEngineResult = engine.unwrap(encryptIn, decryptedIn);
                    encryptIn.compact();
                } catch (IllegalStateException ise) {
                    log.debug("Ignoring exception in close()");
                }
                break;
            case NEED_WRAP:
                log.debug("{0} NEED_WRAP", channel.socket().getRemoteSocketAddress());
                decryptedOut.flip();
                sslEngineResult = engine.wrap(decryptedOut, encryptedOut);
                decryptedOut.compact();
                if (sslEngineResult.getStatus() == SSLEngineResult.Status.CLOSED) {
                	 count = flush();
                }else {
                    count = flush();
                }
                break;
            case FINISHED:
                log.debug("{0} FINISHED", channel.socket().getRemoteSocketAddress());
                handshakePending = false;
                log.info("--------processHandshake status: "+ status);
                // Indicate to the associated handshake listener that the handshake is complete
                //hsListener.handshakeComplete(this);
            case NOT_HANDSHAKING:
                log.debug("{0} NOT_HANDSHAKING", channel.socket().getRemoteSocketAddress());
                // handshake has been completed at this point, no need to 
                // check the status of the SSLEngineResult;
                handshakePending = false;
                log.info("--------processHandshake status: "+ status);
                return;
        }
        
		if(sslEngineResult!=null)
		{
        // Check the result of the preceding wrap or unwrap.
        switch (sslEngineResult.getStatus()) {
            case BUFFER_UNDERFLOW:
                // Return as we do not have enough data to continue processing the handshake
                log.debug("{0} BUFFER_UNDERFLOW", channel.socket().getRemoteSocketAddress());
                return;
            case BUFFER_OVERFLOW:
                log.debug("{0} BUFFER_OVERFLOW", channel.socket().getRemoteSocketAddress());
                // Return as the encrypted buffer has not been cleared yet
                return;
            case CLOSED:
                log.debug("{0} CLOSED", channel.socket().getRemoteSocketAddress());
                if (engine.isOutboundDone()) {
                    channel.socket().shutdownOutput();// stop sending
                }
                return;
            case OK:
                log.debug("{0} OK", channel.socket().getRemoteSocketAddress());
                // handshaking can continue.
                break;
        }
		}
        processHandshake();
    }

    private int flush() throws IOException {
        // Selector temp = null;
        encryptedOut.flip();
        int remaining = encryptedOut.remaining();
        System.out.println("Encrypted out remaining: " + remaining);
        int countOut = 0;
        int count;
        int retries = 0;
        
        while(encryptedOut.hasRemaining()){
            count = channel.write(encryptedOut);
            countOut += count;
            retries++;
        }encryptedOut.compact();


        log.debug("{0} Flushed {1} bytes, {2} retries.", new Object[]{channel.socket().getRemoteSocketAddress(),
                    countOut, retries <= 1 ? 0 : retries});
        return countOut;
    }
    private void runDelegatedTasks() {
            // Run the delegated tasks in the same thread 
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
            	//tasks.add( exec.submit( task ) );
            	task.run();
            }
            // Update the SSLEngineResult
           // updateResult();
        
    }
    
    //@Override
//    public void updateResult() {
//    	readEngineResult = new SSLEngineResult(
//    			readEngineResult.getStatus(),
//                engine.getHandshakeStatus(),
//                readEngineResult.bytesProduced(),
//                readEngineResult.bytesConsumed());
//    }
    
//    public void processHandshake() throws IOException {//synchronized 
//		if( engine.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING )
//		{
//			log.info("----------processHandshake done: NOT_HANDSHAKING");
//			return; // since this may be called either from a reading or a writing thread and because this method is synchronized it is necessary to double check if we are still handshaking.
//		}
//
//		if( engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP ) {
//			log.info("----------processHandshake : HandshakeStatus.NEED_UNWRAP");
//			if( !isBlocking() || readEngineResult.getStatus() == Status.BUFFER_UNDERFLOW ) {
//				encryptIn.compact();
//				int read = channel.read( encryptIn );
//				if( read == -1 ) {
//					throw new IOException( "connection closed unexpectedly by peer" );
//				}
//				encryptIn.flip();
//			}
//			decryptedIn.compact();
//			unwrap();
//			if( readEngineResult.getHandshakeStatus() == HandshakeStatus.FINISHED ) {
//				log.info("----------processHandshake done: HandshakeStatus.FINISHED");
//				createBuffers( engine.getSession() );
//				return;
//			}
//		}
//		consumeDelegatedTasks();
//		// tasks.isEmpty() || 
//		if(engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP ) {
//			log.info("----------processHandshake : HandshakeStatus.NEED_WRAP");
//			 bytesToWrite.offer(emptybuffer);
//			 bytesToWriteRemaining += 1;
//			tryWriteBytes();
//	         //setWriteOps();
//			if( writeEngineResult.getHandshakeStatus() == HandshakeStatus.FINISHED ) {
//				createBuffers( engine.getSession() );
//				return;
//			}
////			appSendBuf.flip();
////		      engineResult = engine.wrap(decryptedOut, packetSendBuf);
////		      handshakeStatus = engineResult.getHandshakeStatus();
////		      appSendBuf.compact();
////
////		      switch (writeEngineResult.getStatus())
////		      {
////		      case BUFFER_OVERFLOW:
////		        nBytes = handleWrite(socketChannel);
////		        break;
////
////		      case OK:
////		        while (packetSendBuf.position() > 0)
////		        {
////		          nBytes = handleWrite(socketChannel);
////		          if (nBytes == 0)
////		          {
////		            // Prevent spinning if the channel refused the write
////		            break;
////		          }
////		        }
////
////		        break;
////
////		      default:
////		        if (TRACER.isEnabled())
////		        {
////		          TRACER.trace("Need Wrap Operation: cannot handle ssl result status [" + engineResult.getStatus() + "]"); //$NON-NLS-1$
////		        }
////		      }
//		}
//		//assert ( engine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING );// this function could only leave NOT_HANDSHAKING after createBuffers was called unless #190 occurs which means that nio wrap/unwrap never return HandshakeStatus.FINISHED
//
//		bufferallocations = 1; // look at variable declaration why this line exists and #190. Without this line buffers would not be be recreated when #190 AND a rehandshake occur.
//	}
    
    protected void createBuffers( SSLSession session ) {
		int netBufferMax = session.getPacketBufferSize();
		int appBufferMax = Math.max(session.getApplicationBufferSize(), netBufferMax);

		if( decryptedIn == null ) {
			decryptedIn = ByteBuffer.allocate( appBufferMax );
			encryptedOut = ByteBuffer.allocate( netBufferMax );
			encryptIn = ByteBuffer.allocate( netBufferMax );
		} else {
			if( decryptedIn.capacity() != appBufferMax )
				decryptedIn = ByteBuffer.allocate( appBufferMax );
			if( encryptedOut.capacity() != netBufferMax )
				encryptedOut = ByteBuffer.allocate( netBufferMax );
			if( encryptIn.capacity() != netBufferMax )
				encryptIn = ByteBuffer.allocate( netBufferMax );
		}
		decryptedIn.rewind();
		decryptedIn.flip();
		encryptIn.rewind();
		encryptIn.flip();
		encryptedOut.rewind();
		encryptedOut.flip();
		bufferallocations++;
		log.info("----------createBuffers done: {}", bufferallocations);
	}

//    private synchronized ByteBuffer wrap( ByteBuffer b ) throws SSLException {
//		encryptedOut.compact();
//		writeEngineResult = engine.wrap( b, encryptedOut );
//		encryptedOut.flip();
//		return encryptedOut;
//	}
    //@Override
	public boolean isBlocking() {
		return channel.isBlocking();
	}
	/**
	 * performs the unwrap operation by unwrapping from {@link #encryptIn} to {@link #inData}
	 **/
//	private synchronized ByteBuffer unwrap() throws SSLException {
//		int rem;
//		do {
//			rem = decryptedIn.remaining();
//			readEngineResult = engine.unwrap( encryptIn, decryptedIn );
//			//TODO
//			try {
//				int bytesConsumed = checkNotNull(connection).receiveBytes(decryptedIn);
//			} catch (Exception e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//            
//		} while ( readEngineResult.getStatus() == SSLEngineResult.Status.OK && ( rem != decryptedIn.remaining() || engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP ) );
//		decryptedIn.flip();
//		return decryptedIn;
//	}
//	
	public boolean isHandShakeComplete() {
//		HandshakeStatus status = engine.getHandshakeStatus();
//		log.info("----------isHandShakeComplete status: {}",status);
//		boolean isCompleted = (status == SSLEngineResult.HandshakeStatus.FINISHED || status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING);
//		return isCompleted;
		return !(this.handshakePending);
	}
	protected void consumeDelegatedTasks() {
//		Runnable task;
//		while ( ( task = engine.getDelegatedTask() ) != null ) {
//			tasks.add( exec.submit( task ) );
//			// task.run();
//		}
	}
}
