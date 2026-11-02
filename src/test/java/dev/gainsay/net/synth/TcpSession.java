package dev.gainsay.net.synth;

/** Scripts one TCP conversation with correct sequence numbers. */
public final class TcpSession {

    static final int SYN = 0x02, ACK = 0x10, PSH = 0x08, RST = 0x04, FIN = 0x01;

    private final Capture cap;
    private final String cMac, cIp, sMac, sIp;
    private final int cPort, sPort;
    private long cSeq = 1000, sSeq = 50_000;

    TcpSession(Capture cap, String cMac, String cIp, int cPort, String sMac, String sIp, int sPort) {
        this.cap = cap;
        this.cMac = cMac;
        this.cIp = cIp;
        this.cPort = cPort;
        this.sMac = sMac;
        this.sIp = sIp;
        this.sPort = sPort;
    }

    private byte[] frame(boolean fromClient, int flags, long seq, long ack, byte[] payload) {
        String srcIp = fromClient ? cIp : sIp;
        String dstIp = fromClient ? sIp : cIp;
        byte[] seg = Frames.tcp(fromClient ? cPort : sPort, fromClient ? sPort : cPort, seq, ack, flags, payload);
        return Frames.ethernet(fromClient ? cMac : sMac, fromClient ? sMac : cMac, srcIp.contains(":") ? 0x86DD : 0x0800,
                Frames.ip(srcIp, dstIp, 6, seg));
    }

    public TcpSession handshake() {
        cap.add(frame(true, SYN, cSeq, 0, new byte[0]));
        cSeq++;
        cap.add(frame(false, SYN | ACK, sSeq, cSeq, new byte[0]));
        sSeq++;
        cap.add(frame(true, ACK, cSeq, sSeq, new byte[0]));
        return this;
    }

    /** SYN answered by RST (closed port). */
    public TcpSession refused() {
        cap.add(frame(true, SYN, cSeq, 0, new byte[0]));
        cap.add(frame(false, RST | ACK, 0, cSeq + 1, new byte[0]));
        return this;
    }

    public TcpSession client(byte[] data) {
        cap.add(frame(true, PSH | ACK, cSeq, sSeq, data));
        cSeq += data.length;
        return this;
    }

    public TcpSession server(byte[] data) {
        cap.add(frame(false, PSH | ACK, sSeq, cSeq, data));
        sSeq += data.length;
        return this;
    }

    /** Sends data from the client in two segments (to exercise reassembly). */
    public TcpSession clientSplit(byte[] data, int at) {
        client(java.util.Arrays.copyOfRange(data, 0, at));
        return client(java.util.Arrays.copyOfRange(data, at, data.length));
    }

    public TcpSession serverReset() {
        cap.add(frame(false, RST | ACK, sSeq, cSeq, new byte[0]));
        return this;
    }

    public TcpSession close() {
        cap.add(frame(true, FIN | ACK, cSeq, sSeq, new byte[0]));
        cSeq++;
        cap.add(frame(false, FIN | ACK, sSeq, cSeq, new byte[0]));
        return this;
    }
}
