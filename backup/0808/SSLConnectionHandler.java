package org.bitcoinj.net;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;

import org.bitcoinj.core.Message;
import org.bitcoinj.utils.Threading;
import org.slf4j.LoggerFactory;

import com.google.common.base.Throwables;

public class SSLConnectionHandler implements MessageWriteTarget {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(SSLConnectionHandler.class);

    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    private static final int OUTBOUND_BUFFER_BYTE_COUNT = Message.MAX_SIZE + 24; // 24 byte message header

    // We lock when touching local flags and when writing data, but NEVER when calling any methods which leave this
    // class into non-Java classes.
    private final ReentrantLock lock = Threading.lock("nioSSLConnectionHandler");
    @GuardedBy("lock") private final ByteBuffer encryptIn;
    @GuardedBy("lock") private final SocketChannel channel;
    @GuardedBy("lock") private final SelectionKey key;
    @GuardedBy("lock") StreamConnection connection;
    @GuardedBy("lock") private boolean closeCalled = false;

    @GuardedBy("lock") private long bytesToWriteRemaining = 0;//decryptedOut
    @GuardedBy("lock") private final LinkedList<ByteBuffer> bytesToWrite = new LinkedList<ByteBuffer>();

    @GuardedBy("lock") private final ByteBuffer encryptedOut;
    @GuardedBy("lock") private final ByteBuffer decryptedIn;//decryptIn
	
    private Set<SSLConnectionHandler> connectedHandlers;
    private SSLEngineResult writeEngineResult = null;
    private SSLEngineResult readEngineResult = null;
    private final SSLEngine engine;
    
    public SSLConnectionHandler(StreamConnectionFactory connectionFactory, SelectionKey key, SSLEngine engine) throws IOException {
        this(connectionFactory.getNewConnection(((SocketChannel) key.channel()).socket().getInetAddress(), ((SocketChannel) key.channel()).socket().getPort()), key, engine);
        if (connection == null)
            throw new IOException("Parser factory.getNewConnection returned null");
    }

    private SSLConnectionHandler(@Nullable StreamConnection connection, SelectionKey key, SSLEngine engine) {
        this.key = key;
        this.channel = checkNotNull(((SocketChannel)key.channel()));
        this.engine = engine;
        if (connection == null) {
            encryptIn = null;
            encryptedOut = null;
            decryptedIn = null;
            return;
        }
        this.connection = connection;
        //readBuff = ByteBuffer.allocateDirect(Math.min(Math.max(connection.getMaxMessageSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        encryptIn = ByteBuffer.allocateDirect(Math.min(Math.max(engine.getSession().getPacketBufferSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        connection.setWriteTarget(this); // May callback into us (eg closeConnection() now)
        connectedHandlers = null;
        
        int appBufSize = engine.getSession().getApplicationBufferSize();
        int netBufSize = engine.getSession().getPacketBufferSize();
        encryptedOut = ByteBuffer.allocate(netBufSize);
        decryptedIn = ByteBuffer.allocate(appBufSize);
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
    private void tryWriteBytes() throws IOException {
        lock.lock();
        try {
            // Iterate through the outbound ByteBuff queue, pushing as much as possible into the OS' network buffer.
            Iterator<ByteBuffer> bytesIterator = bytesToWrite.iterator();
            while (bytesIterator.hasNext()) {
                ByteBuffer buff = bytesIterator.next();
                bytesToWriteRemaining -= channel.write(buff);
                if (!buff.hasRemaining())
                    bytesIterator.remove();
                else {
                    setWriteOps();
                    break;
                }
            }
            // If we are done writing, clear the OP_WRITE interestOps
            if (bytesToWrite.isEmpty())
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
            // Don't bother waking up the selector here, since we're just removing an op, not adding
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void writeBytes(byte[] message) throws IOException {
        boolean andUnlock = true;
        lock.lock();
        try {
            // Network buffers are not unlimited (and are often smaller than some messages we may wish to send), and
            // thus we have to buffer outbound messages sometimes. To do this, we use a queue of ByteBuffers and just
            // append to it when we want to send a message. We then let tryWriteBytes() either send the message or
            // register our SelectionKey to wakeup when we have free outbound buffer space available.

            if (bytesToWriteRemaining + message.length > OUTBOUND_BUFFER_BYTE_COUNT)
                throw new IOException("Outbound buffer overflowed");
            
			// Just dump the message onto the write buffer and call tryWriteBytes
            // TODO: Kill the needless message duplication when the write completes right away
            //bytesToWrite.offer(ByteBuffer.wrap(Arrays.copyOf(message, message.length)));
            //encryptedOut.clear
            writeEngineResult = engine.wrap(ByteBuffer.wrap(Arrays.copyOf(message, message.length)), encryptedOut);
            log.info("---------engine.wrap writeEngineResult: "+writeEngineResult+" status:"+writeEngineResult.getStatus()+" handshake:"+writeEngineResult.getHandshakeStatus());
            bytesToWrite.offer(encryptedOut);
           
            bytesToWriteRemaining += message.length;
            setWriteOps();
        } catch (IOException e) {
            lock.unlock();
            andUnlock = false;
            log.warn("Error writing message to connection, closing connection", e);
            closeConnection();
            throw e;
        } catch (CancelledKeyException e) {
            lock.unlock();
            andUnlock = false;
            log.warn("Error writing message to connection, closing connection", e);
            closeConnection();
            throw new IOException(e);
        } finally {
            if (andUnlock)
                lock.unlock();
        }
    }

    // May NOT be called with lock held
    @Override
    public void closeConnection() {
        checkState(!lock.isHeldByCurrentThread());
        try {
            // Flush any pending encrypted output data
           // flush();
            if (!engine.isOutboundDone()) {
                engine.closeOutbound();
            //    processHandshake();
                
            } else if (!engine.isInboundDone()) {
                // Closing inbound will throw an SSLException if we have not
                // received a close_notify.
                engine.closeInbound();
                // Process what we can before we close the channel.
            //    processHandshake();
            }
        } catch (SSLException e) {
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
            if (!key.isValid()) {
                handler.closeConnection(); // Key has been cancelled, make sure the socket gets closed
                return;
            }
            if (key.isReadable()) {
                // Do a socket read and invoke the connection's receiveBytes message
                int read = handler.channel.read(handler.encryptIn);
                if (read == 0)
                    return; // Was probably waiting on a write
                else if (read == -1) { // Socket was closed
                    key.cancel();
                    handler.closeConnection();
                    return;
                }
                // "flip" the buffer - setting the limit to the current position and setting position to 0
                handler.encryptIn.flip();
                handler.readEngineResult = handler.engine.unwrap(handler.encryptIn, handler.decryptedIn);
                // Use connection.receiveBytes's return value as a check that it stopped reading at the right location
                //int bytesConsumed = checkNotNull(handler.connection).receiveBytes(handler.readBuff);
                int bytesConsumed = checkNotNull(handler.connection).receiveBytes(handler.decryptedIn);
                checkState(handler.encryptIn.position() == bytesConsumed);
                // Now drop the bytes which were read by compacting readBuff (resetting limit and keeping relative
                // position)
                handler.encryptIn.compact();
            }
            if (key.isWritable())
                handler.tryWriteBytes();
        } catch (Exception e) {
            // This can happen eg if the channel closes while the thread is about to get killed
            // (ClosedByInterruptException), or if handler.connection.receiveBytes throws something
            Throwable t = Throwables.getRootCause(e);
            log.warn("Error handling SelectionKey: {}", t.getMessage() != null ? t.getMessage() : t.getClass().getName());
            handler.closeConnection();
        }
    }
    
//    private synchronized void processHandshake() throws IOException {
//		if( engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING )
//			return; // since this may be called either from a reading or a writing thread and because this method is synchronized it is necessary to double check if we are still handshaking.
//		 SSLConnectionHandler handler = ((SSLConnectionHandler)key.attachment());
//		if( !tasks.isEmpty() ) {
//			Iterator<Future<?>> it = tasks.iterator();
//			while ( it.hasNext() ) {
//				Future<?> f = it.next();
//				if( f.isDone() ) {
//					it.remove();
//				} else {
//					if( isBlocking() )
//						consumeFutureUninterruptible( f );
//					return;
//				}
//			}
//		}
//
//		if( engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP ) {
//			if( !isBlocking() || readEngineResult.getStatus() == Status.BUFFER_UNDERFLOW ) {
//				inCrypt.compact();
//				int read = handler.channel.read( inCrypt );
//				if( read == -1 ) {
//					throw new IOException( "connection closed unexpectedly by peer" );
//				}
//				inCrypt.flip();
//			}
//			inData.compact();
//			unwrap();
//			if( readEngineResult.getHandshakeStatus() == HandshakeStatus.FINISHED ) {
//				createBuffers( engine.getSession() );
//				return;
//			}
//		}
//		consumeDelegatedTasks();
//		if( tasks.isEmpty() || engine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP ) {
//			handler.channel.write( wrap( emptybuffer ) );
//			if( writeEngineResult.getHandshakeStatus() == HandshakeStatus.FINISHED ) {
//				createBuffers( engine.getSession() );
//				return;
//			}
//		}
//		assert ( engine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING );// this function could only leave NOT_HANDSHAKING after createBuffers was called unless #190 occurs which means that nio wrap/unwrap never return HandshakeStatus.FINISHED
//
//		bufferallocations = 1; // look at variable declaration why this line exists and #190. Without this line buffers would not be be recreated when #190 AND a rehandshake occur.
//	}
}
