package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * HOST-AUDIT-001. Implementation: {@code auditpol /get /category:* /r} (CSV: Machine Name, Policy Target,
 * Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting). Subcategories are matched by GUID,
 * which is locale-independent; the inclusion text is parsed in English ("Success", "Failure",
 * "Success and Failure", "No Auditing"). Needs elevation.
 */
public final class AuditPolicyCheck extends AbstractCheck {

    /** GUID → (name, needs success, needs failure). A practical subset of the Microsoft/CIS baselines. */
    public record Expectation(String name, boolean success, boolean failure) {
    }

    public static final Map<String, Expectation> EXPECTED = new LinkedHashMap<>();

    static {
        EXPECTED.put("{0CCE923F-69AE-11D9-BED3-505054503030}", new Expectation("Credential Validation", true, true));
        EXPECTED.put("{0CCE9215-69AE-11D9-BED3-505054503030}", new Expectation("Logon", true, true));
        EXPECTED.put("{0CCE9217-69AE-11D9-BED3-505054503030}", new Expectation("Account Lockout", false, true));
        EXPECTED.put("{0CCE921B-69AE-11D9-BED3-505054503030}", new Expectation("Special Logon", true, false));
        EXPECTED.put("{0CCE9235-69AE-11D9-BED3-505054503030}", new Expectation("User Account Management", true, true));
        EXPECTED.put("{0CCE9237-69AE-11D9-BED3-505054503030}", new Expectation("Security Group Management", true, false));
        EXPECTED.put("{0CCE922B-69AE-11D9-BED3-505054503030}", new Expectation("Process Creation", true, false));
        EXPECTED.put("{0CCE922F-69AE-11D9-BED3-505054503030}", new Expectation("Audit Policy Change", true, false));
        EXPECTED.put("{0CCE9228-69AE-11D9-BED3-505054503030}", new Expectation("Sensitive Privilege Use", true, true));
        EXPECTED.put("{0CCE9211-69AE-11D9-BED3-505054503030}", new Expectation("Security System Extension", true, false));
    }

    public AuditPolicyCheck() {
        super("HOST-AUDIT-001", "Key audit policy subcategories are enabled", Categories.AUDITING, Severity.MEDIUM,
                "Without logon, account-management and process-creation auditing, the Security log cannot answer 'who logged on, what changed, "
                        + "what ran' after an incident.",
                "Parsed auditpol /get /category:* /r and compared 10 subcategories (by GUID) with a baseline subset.",
                "Configure Advanced Audit Policy via Group Policy (Computer Configuration > Windows Settings > Security Settings > Advanced Audit "
                        + "Policy Configuration), e.g. auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable.",
                List.of("https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"));
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("auditpol");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        Map<String, String> settings = new HashMap<>();
        for (JsonNode n : q.list()) {
            String[] cols = n.asText("").split(",", -1);
            if (cols.length >= 5 && cols[3].startsWith("{")) {
                settings.put(cols[3].trim().toUpperCase(Locale.ROOT), cols[4].trim());
            }
        }
        if (settings.isEmpty()) {
            return unknown(ds, "auditpol output could not be parsed", List.of());
        }
        List<String> missing = new ArrayList<>();
        List<Evidence> ev = new ArrayList<>();
        int unparsed = 0;
        for (Map.Entry<String, Expectation> e : EXPECTED.entrySet()) {
            String s = settings.getOrDefault(e.getKey(), "");
            String l = s.toLowerCase(Locale.ROOT);
            boolean recognised = l.contains("success") || l.contains("failure") || l.contains("no auditing");
            if (!recognised) {
                unparsed++;
                continue;
            }
            boolean ok = (!e.getValue().success() || l.contains("success")) && (!e.getValue().failure() || l.contains("failure"));
            if (!ok) {
                missing.add(e.getValue().name() + " (has: " + s + ")");
                ev.add(new Evidence("command", "auditpol " + e.getKey(), e.getValue().name() + ": " + s,
                        "auditpol /get /subcategory:\"" + e.getValue().name() + "\"   # elevated"));
            }
        }
        if (unparsed == EXPECTED.size()) {
            return unknown(ds, "auditpol settings are not in English; cannot interpret them", List.of());
        }
        if (missing.isEmpty()) {
            return pass(ds, "All " + (EXPECTED.size() - unparsed) + " baseline audit subcategories are enabled.", ev);
        }
        String summary = missing.size() + " baseline subcategories are not fully audited: " + String.join("; ", missing) + ".";
        return missing.size() > EXPECTED.size() / 2 ? fail(ds, summary, ev) : warn(ds, summary, ev);
    }
}
