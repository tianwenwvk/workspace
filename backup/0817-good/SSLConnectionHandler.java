/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.net;

import org.bitcoinj.core.Message;
import org.bitcoinj.utils.Threading;
import com.google.common.base.Throwables;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

// TODO: The locking in all this class is horrible and not really necessary. We should just run all network stuff on one thread.

/**
 * A simple NIO MessageWriteTarget which handles all the business logic of a connection (reading+writing bytes).
 * Used only by the NioClient and NioServer classes
 */
class SSLConnectionHandler implements MessageWriteTarget {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(SSLConnectionHandler.class);

    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    private static final int OUTBOUND_BUFFER_BYTE_COUNT = Message.MAX_SIZE + 24; // 24 byte message header

    // We lock when touching local flags and when writing data, but NEVER when calling any methods which leave this
    // class into non-Java classes.
    private final ReentrantLock lock = Threading.lock("nioConnectionHandler");
   // @GuardedBy("lock") private final ByteBuffer readBuff;
    @GuardedBy("lock") private final SocketChannel channel;
    @GuardedBy("lock") private final SelectionKey key;
    @GuardedBy("lock") StreamConnection connection;
    @GuardedBy("lock") private boolean closeCalled = false;

    @GuardedBy("lock") private long bytesToWriteRemaining = 0;
    @GuardedBy("lock") private final LinkedList<ByteBuffer> bytesToWrite = new LinkedList<ByteBuffer>();

    private Set<SSLConnectionHandler> connectedHandlers;
    
    @GuardedBy("lock") private ByteBuffer peerAppData;
    @GuardedBy("lock") private ByteBuffer peerNetData;
    @GuardedBy("lock") private ByteBuffer myAppData;
    @GuardedBy("lock") private ByteBuffer myNetData;
   	protected int netBufferMax;
   	protected int appBufferMax;
   	private SSLEngine engine;
   	
   	protected ExecutorService executor = Executors.newSingleThreadExecutor();
   	
    public SSLConnectionHandler(StreamConnectionFactory connectionFactory, SelectionKey key, SSLEngine engine) throws IOException {
        this(connectionFactory.getNewConnection(((SocketChannel) key.channel()).socket().getInetAddress(), ((SocketChannel) key.channel()).socket().getPort()), key, engine);
        if (connection == null)
            throw new IOException("Parser factory.getNewConnection returned null");
    }

    private SSLConnectionHandler(@Nullable StreamConnection connection, SelectionKey key, SSLEngine engine) {
        this.key = key;
        this.channel = checkNotNull(((SocketChannel)key.channel()));
        if (connection == null) {
            //readBuff = null;
            return;
        }
        this.connection = connection;
        //readBuff = ByteBuffer.allocateDirect(Math.min(Math.max(connection.getMaxMessageSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        connection.setWriteTarget(this); // May callback into us (eg closeConnection() now)
        connectedHandlers = null;
        this.engine = engine;
        //int appBufferSize = engine.getSession().getApplicationBufferSize();
        netBufferMax = Math.min(Math.max(engine.getSession().getPacketBufferSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND);
		appBufferMax = Math.min(Math.max(engine.getSession().getApplicationBufferSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND);
		
        myAppData = ByteBuffer.allocate(appBufferMax);
        peerAppData = ByteBuffer.allocate(appBufferMax);
        myNetData = ByteBuffer.allocate(netBufferMax);
        peerNetData = ByteBuffer.allocate(netBufferMax);
    }

    public SSLConnectionHandler(StreamConnection connection, SelectionKey key, Set<SSLConnectionHandler> connectedHandlers, SSLEngine engine) {
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
            boolean wrapResult = wrap(Arrays.copyOf(message, message.length));
            if(wrapResult)
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

    protected boolean wrap(byte[] message) throws IOException {

        log.debug("About to wrap to the server...");
        ByteBuffer encryptedMessage = ByteBuffer.allocate(netBufferMax);
        myAppData.clear();
        myAppData.put(message);
        myAppData.flip();
        while (myAppData.hasRemaining()) {
            // The loop has a meaning for (outgoing) messages larger than 16KB.
            // Every wrap call will remove 16KB from the original message and send it to the remote peer.
        	encryptedMessage.clear();
            SSLEngineResult result = engine.wrap(myAppData, encryptedMessage);
            switch (result.getStatus()) {
            case OK:
            	encryptedMessage.flip();
//                while (myNetData.hasRemaining()) {
//                    channel.write(myNetData);
//                }
                bytesToWrite.offer(encryptedMessage);
                bytesToWriteRemaining += message.length;
                log.debug("Message sent to the server: " + message);
                break;
            case BUFFER_OVERFLOW:
            	encryptedMessage = enlargePacketBuffer(engine, encryptedMessage);
                break;
            case BUFFER_UNDERFLOW:
                throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
            case CLOSED:
                closeConnection();
                return false;
            default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }
        }
        return true;
    }
    
    // May NOT be called with lock held
    @Override
    public void closeConnection() {
        checkState(!lock.isHeldByCurrentThread());
        try {
        	engine.closeOutbound();
            doHandshake(channel, engine);
            channel.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
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
    // atomically for a given ConnectionHandler)
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
                boolean upwrapResult = handler.unwrap();
                if(!upwrapResult) return;
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
    
    protected boolean unwrap() throws Exception  {

        log.debug("About to unwrap from the server...");

        peerNetData.clear();
        int waitToReadMillis = 50;
        boolean exitReadLoop = false;
        while (!exitReadLoop) {
            int bytesRead = channel.read(peerNetData);
            if (bytesRead > 0) {
                peerNetData.flip();
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear();
                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                    switch (result.getStatus()) {
                    case OK:
                        peerAppData.flip();
                        int bytesConsumed = checkNotNull(connection).receiveBytes(peerAppData);
                        checkState(peerAppData.position() == bytesConsumed);
                        peerAppData.compact();
                        log.debug("Server response: " + new String(peerAppData.array()));
                        exitReadLoop = true;
                        break;
                    case BUFFER_OVERFLOW:
                        peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                        break;
                    case BUFFER_UNDERFLOW:
                        peerNetData = handleBufferUnderflow(engine, peerNetData);
                        break;
                    case CLOSED:
                        closeConnection();
                        return false;
                    default:
                        throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                }
            } else if (bytesRead < 0) {
                handleEndOfStream();
                return false;
            }
            Thread.sleep(waitToReadMillis);
        }
        
        return true;
    }
    
    protected void handleEndOfStream() throws IOException  {
        try {
            engine.closeInbound();
        } catch (Exception e) {
            log.error("This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
        }
        closeConnection();
    }

	protected boolean doHandshake(SocketChannel socketChannel, SSLEngine engine) throws IOException {

        log.debug("About to do handshake...");

        SSLEngineResult result;
        HandshakeStatus handshakeStatus;
        
        myNetData.clear();
        peerNetData.clear();

        handshakeStatus = engine.getHandshakeStatus();
        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch (handshakeStatus) {
            case NEED_UNWRAP:
                if (socketChannel.read(peerNetData) < 0) {
                    if (engine.isInboundDone() && engine.isOutboundDone()) {
                        return false;
                    }
                    try {
                        engine.closeInbound();
                    } catch (SSLException e) {
                        log.error("This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
                    }
                    engine.closeOutbound();
                    // After closeOutbound the engine will be set to WRAP state, in order to try to send a close message to the client.
                    handshakeStatus = engine.getHandshakeStatus();
                    break;
                }
                peerNetData.flip();
                try {
                    result = engine.unwrap(peerNetData, peerAppData);
                    peerNetData.compact();
                    handshakeStatus = result.getHandshakeStatus();
                } catch (SSLException sslException) {
                    log.error("A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
                    engine.closeOutbound();
                    handshakeStatus = engine.getHandshakeStatus();
                    break;
                }
                switch (result.getStatus()) {
                case OK:
                    break;
                case BUFFER_OVERFLOW:
                    // Will occur when peerAppData's capacity is smaller than the data derived from peerNetData's unwrap.
                    peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                    break;
                case BUFFER_UNDERFLOW:
                    // Will occur either when no data was read from the peer or when the peerNetData buffer was too small to hold all peer's data.
                    peerNetData = handleBufferUnderflow(engine, peerNetData);
                    break;
                case CLOSED:
                    if (engine.isOutboundDone()) {
                        return false;
                    } else {
                        engine.closeOutbound();
                        handshakeStatus = engine.getHandshakeStatus();
                        break;
                    }
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                }
                break;
            case NEED_WRAP:
                myNetData.clear();
                try {
                    result = engine.wrap(myAppData, myNetData);
                    handshakeStatus = result.getHandshakeStatus();
                } catch (SSLException sslException) {
                    log.error("A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
                    engine.closeOutbound();
                    handshakeStatus = engine.getHandshakeStatus();
                    break;
                }
                switch (result.getStatus()) {
                case OK :
                    myNetData.flip();
                    while (myNetData.hasRemaining()) {
                        socketChannel.write(myNetData);
                    }
                    break;
                case BUFFER_OVERFLOW:
                    // Will occur if there is not enough space in myNetData buffer to write all the data that would be generated by the method wrap.
                    // Since myNetData is set to session's packet size we should not get to this point because SSLEngine is supposed
                    // to produce messages smaller or equal to that, but a general handling would be the following:
                    myNetData = enlargePacketBuffer(engine, myNetData);
                    break;
                case BUFFER_UNDERFLOW:
                    throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
                case CLOSED:
                    try {
                        myNetData.flip();
                        while (myNetData.hasRemaining()) {
                            socketChannel.write(myNetData);
                        }
                        // At this point the handshake status will probably be NEED_UNWRAP so we make sure that peerNetData is clear to read.
                        peerNetData.clear();
                    } catch (Exception e) {
                        log.error("Failed to send server's CLOSE message due to socket channel's failure.");
                        handshakeStatus = engine.getHandshakeStatus();
                    }
                    break;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                }
                break;
            case NEED_TASK:
                Runnable task;
                while ((task = engine.getDelegatedTask()) != null) {
                    executor.execute(task);
                }
                handshakeStatus = engine.getHandshakeStatus();
                break;
            case FINISHED:
                break;
            case NOT_HANDSHAKING:
                break;
            default:
                throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
            }
        }

        return true;

    }

    protected ByteBuffer enlargePacketBuffer(SSLEngine engine, ByteBuffer buffer) {
        return enlargeBuffer(buffer, engine.getSession().getPacketBufferSize());
    }

    protected ByteBuffer enlargeApplicationBuffer(SSLEngine engine, ByteBuffer buffer) {
        return enlargeBuffer(buffer, engine.getSession().getApplicationBufferSize());
    }
    
    protected ByteBuffer enlargeBuffer(ByteBuffer buffer, int sessionProposedCapacity) {
        if (sessionProposedCapacity > buffer.capacity()) {
            buffer = ByteBuffer.allocate(sessionProposedCapacity);
        } else {
            buffer = ByteBuffer.allocate(buffer.capacity() * 2);
        }
        return buffer;
    }

    protected ByteBuffer handleBufferUnderflow(SSLEngine engine, ByteBuffer buffer) {
        if (buffer.position() < buffer.limit()) {
            return buffer;
        } else {
            ByteBuffer replaceBuffer = enlargePacketBuffer(engine, buffer);
            buffer.flip();
            replaceBuffer.put(buffer);
            return replaceBuffer;
        }
    }
    
}
