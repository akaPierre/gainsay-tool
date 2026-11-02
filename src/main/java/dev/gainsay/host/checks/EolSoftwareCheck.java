package dev.gainsay.host.checks;

import com.fasterxml.jackson.databind.JsonNode;
import dev.gainsay.core.Evidence;
import dev.gainsay.core.Finding;
import dev.gainsay.core.Severity;
import dev.gainsay.host.AbstractCheck;
import dev.gainsay.host.HostPolicy;
import dev.gainsay.host.HostPolicy.EolEntry;
import dev.gainsay.host.source.HostDataSource;
import dev.gainsay.host.source.QueryResult;

import java.util.ArrayList;
import java.util.List;

/**
 * HOST-SW-001. Implementation: installed programs are the subkeys of
 * {@code HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall} (64-bit) and
 * {@code HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall} (32-bit), with
 * {@code DisplayName}/{@code DisplayVersion}. They are compared to the local, user-editable
 * {@code eol-software.txt} using plain substring and prefix tests (no regex, no network).
 * Per-user installs under HKCU are not covered.
 */
public final class EolSoftwareCheck extends AbstractCheck {

    private final List<EolEntry> list;

    public EolSoftwareCheck(HostPolicy policy) {
        super("HOST-SW-001", "No end-of-life or known-risky software is installed", Categories.SOFTWARE, Severity.MEDIUM,
                "Software that no longer gets updates accumulates exploitable bugs; browsers and document readers are reached directly by attacker content.",
                "Compared installed programs (HKLM Uninstall keys, 64- and 32-bit) with the local end-of-life list.",
                "Uninstall or upgrade the listed programs. Extend the list (--eol-list) with your organisation's own banned software.",
                List.of("https://learn.microsoft.com/lifecycle/"));
        this.list = policy.eolSoftware();
    }

    @Override
    public Finding evaluate(HostDataSource ds) {
        QueryResult q = ds.query("installed.software");
        if (!q.ok()) {
            return unknown(ds, reason(q), List.of());
        }
        List<Evidence> ev = new ArrayList<>();
        List<String> hits = new ArrayList<>();
        int total = 0;
        for (JsonNode p : q.list()) {
            total++;
            String name = p.path("DisplayName").asText("");
            String version = p.path("DisplayVersion").asText("");
            for (EolEntry e : list) {
                if (e.matches(name, version)) {
                    hits.add(name + (version.isEmpty() ? "" : " " + version));
                    ev.add(new Evidence("registry", "Uninstall\\" + name, name + " " + version + " — " + e.reason(),
                            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | ? DisplayName -like '*"
                                    + e.pattern().replace("'", "") + "*' | Select DisplayName, DisplayVersion"));
                    break;
                }
            }
        }
        if (hits.isEmpty()) {
            return pass(ds, "None of " + total + " installed programs is on the end-of-life list (" + list.size() + " entries).", ev);
        }
        return fail(ds, hits.size() + " end-of-life/risky program(s): " + String.join(", ", hits) + ".", ev);
    }
}
