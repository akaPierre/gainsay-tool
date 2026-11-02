package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.List;

/**
 * HOST-EXEC-003. Implementation: {@code Get-ExecutionPolicy -List}. Precedence: MachinePolicy (GPO),
 * UserPolicy, Process, CurrentUser, LocalMachine; the first scope that is not "Undefined" wins.
 * The Process scope is deliberately ignored: it describes the PowerShell process Gainsay itself started
 * (often inherited from the launching shell via PSExecutionPolicyPreference), not the machine.
 * LocalMachine is stored at {@code HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy}.
 *
 * <p>Teaching note in the finding: execution policy is a safety belt against accidents, <em>not</em> a
 * security boundary ({@code powershell -ExecutionPolicy Bypass} is allowed for any user), hence LOW severity.
 */
public final class ExecutionPolicyCheck extends AbstractCheck {

    static final List<String> ORDER = List.of("MachinePolicy", "UserPolicy", "CurrentUser", "LocalMachine");

    public ExecutionPolicyCheck() {
        super("HOST-EXEC-003", "PowerShell execution policy is not Bypass/Unrestricted", Categories.EXECUTION, Severity.LOW,
                "A restrictive execution policy stops users double-clicking downloaded .ps1 files by accident. It is not a security boundary: anyone can "
                        + "run powershell -ExecutionPolicy Bypass, so do not rely on it against an attacker.",
                "Took the effective policy from Get-ExecutionPolicy -List using PowerShell's scope precedence, ignoring the per-process scope "
                        + "(which only describes the query's own PowerShell session).",
                "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine (or via GPO 'Turn on Script Execution'). Use AppLocker/WDAC for real enforcement.",
                List.of("https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("ps.execpolicy");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        String effective = "Undefined";
        String scope = "default";
        for (String s : ORDER) {
            for (JsonNode row : q.list()) {
                if (s.equalsIgnoreCase(row.path("Scope").asText()) && !"Undefined".equalsIgnoreCase(row.path("ExecutionPolicy").asText("Undefined"))) {
                    effective = row.path("ExecutionPolicy").asText();
                    scope = s;
                    break;
                }
            }
            if (!scope.equals("default")) {
                break;
            }
        }
        if (scope.equals("default")) {
            effective = AvProductCheck.isServer(ds) ? "RemoteSigned" : "Restricted"; // Windows defaults
        }
        Evidence ev = queryEvidence("ps.execpolicy", "effective ExecutionPolicy=" + effective + " (scope " + scope + ")", "Get-ExecutionPolicy -List");
        if ("Bypass".equalsIgnoreCase(effective) || "Unrestricted".equalsIgnoreCase(effective)) {
            return warn(ds, "Effective execution policy is " + effective + " (scope " + scope + ").", List.of(ev));
        }
        return pass(ds, "Effective execution policy is " + effective + " (scope " + scope + ").", List.of(ev));
    }
}
