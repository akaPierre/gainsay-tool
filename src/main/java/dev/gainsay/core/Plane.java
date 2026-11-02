package dev.gainsay.core;

/**
 * Where a finding comes from. HOST findings are <em>testimony</em> (what the machine says it is
 * configured to do); NET and SCAN findings are <em>evidence</em> (what was seen happening); TRIAL
 * findings come from cross-examining one against the other.
 */
public enum Plane {
    HOST, NET, SCAN, TRIAL
}
