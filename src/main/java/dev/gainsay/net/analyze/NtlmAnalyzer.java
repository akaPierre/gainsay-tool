package dev.gainsay.net.analyze;

import dev.gainsay.core.Status;
import dev.gainsay.core.verdict.ObservationType;
import dev.gainsay.net.decode.DecodedPacket;
import dev.gainsay.net.decode.NtlmParser;

import java.util.List;

/**
 * NET-SMB-003: NTLMv1 in use, and NTLMv1/v2 evidence for the trial. Looks at client→server stream
 * heads of any TCP connection (SMB session setup, HTTP NTLM/Negotiate, …) and records only response
 * lengths.
 */
public final class NtlmAnalyzer implements Analyzer {

    @Override
    public List<String> checkIds() {
        return List.of("NET-SMB-003");
    }

    @Override
    public void onStream(Flow f, boolean toServer, StreamHead head, DecodedPacket p, AnalysisContext ctx) {
        if (!toServer || f.marked("ntlm.done")) {
            return;
        }
        for (NtlmParser.Authenticate a : NtlmParser.find(head.bytes(), head.length())) {
            f.mark("ntlm.done");
            ctx.relevant("NET-SMB-003");
            String detail = "NTLMSSP AUTHENTICATE: NT response " + a.ntResponseLength() + " bytes, LM response " + a.lmResponseLength()
                    + " bytes → " + (a.ntlmV1() ? "NTLMv1" : "NTLMv2");
            String filter = Filters.host(f.clientIp) + " && ntlmssp.messagetype==0x00000003";
            ctx.observe(a.ntlmV1() ? ObservationType.NTLMV1_SENT : ObservationType.NTLMV2_SENT, f.clientIp, f.clientMac, f.serverIp,
                    f.serverPort, p.ts, ctx.packetEvidence(p, detail, filter));
            if (a.ntlmV1()) {
                ctx.finding("NET-SMB-003", f.clientIp, Status.FAIL, "Host " + f.clientIp + " authenticated to " + f.server() + " with NTLMv1.",
                        ctx.packetEvidence(p, detail, filter), p.ts);
            }
            return;
        }
    }
}
