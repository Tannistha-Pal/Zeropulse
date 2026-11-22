import { useCallback, useEffect, useState } from "react";
import api from "../api";
import { useSocket } from "../socketContextValue";

const MAX_EVENTS = 50;

function eventKey(event) {
    return event.eventId || [
        event.type,
        event.timestamp,
        event.sessionRef
    ].join(":");
}

function mergeEvents(existing, incoming) {
    const unique = new Map();
    [...incoming, ...existing].forEach((event) => {
        const key = eventKey(event);
        if (!unique.has(key)) unique.set(key, event);
    });
    return [...unique.values()]
        .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))
        .slice(0, MAX_EVENTS);
}

function formatDate(value) {
    if (!value) return "Unknown";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function StatusBadge({ status }) {
    return <span className={`badge status-${status.toLowerCase()}`}>{status}</span>;
}

function SeverityBadge({ severity }) {
    const value = (severity || "low").toLowerCase();
    return <span className={`badge severity-${value}`}>{value.toUpperCase()}</span>;
}

export default function Dashboard({ onLogout }) {
    const { socket, status: socketStatus } = useSocket();
    const [sessions, setSessions] = useState([]);
    const [events, setEvents] = useState([]);
    const [sessionsLoading, setSessionsLoading] = useState(true);
    const [eventsLoading, setEventsLoading] = useState(true);
    const [sessionsError, setSessionsError] = useState("");
    const [eventsError, setEventsError] = useState("");
    const [actionMessage, setActionMessage] = useState("");
    const [actionError, setActionError] = useState("");
    const [revokingRef, setRevokingRef] = useState(null);

    useEffect(() => {
        let mounted = true;
        api.get("/user/sessions")
            .then(({ data }) => {
                if (mounted) setSessions(data.sessions || []);
            })
            .catch((error) => {
                if (mounted) {
                    setSessionsError(error.response?.data?.message || "Unable to load sessions.");
                }
            })
            .finally(() => {
                if (mounted) setSessionsLoading(false);
            });

        api.get("/user/threat-events")
            .then(({ data }) => {
                if (mounted) setEvents((current) => mergeEvents(current, data.events || []));
            })
            .catch((error) => {
                if (mounted) {
                    setEventsError(error.response?.data?.message || "Unable to load threat events.");
                }
            })
            .finally(() => {
                if (mounted) setEventsLoading(false);
            });

        return () => {
            mounted = false;
        };
    }, []);

    useEffect(() => {
        if (!socket) return undefined;

        const handleRevocation = (notification) => {
            if (notification?.action !== "REVOKE" || !notification.sessionRef) return;
            setSessions((current) => current.map((session) =>
                session.sessionRef === notification.sessionRef
                    ? { ...session, status: "REVOKED" }
                    : session
            ));
        };
        const handleThreatEvent = (event) => {
            setEvents((current) => mergeEvents(current, [event]));
        };

        socket.on("session_revoked", handleRevocation);
        socket.on("threat_event", handleThreatEvent);
        return () => {
            socket.off("session_revoked", handleRevocation);
            socket.off("threat_event", handleThreatEvent);
        };
    }, [socket]);

    const killSession = useCallback(async (session) => {
        setRevokingRef(session.sessionRef);
        setActionMessage("");
        setActionError("");
        try {
            await api.post("/auth/revoke-session", {
                sessionRef: session.sessionRef
            });
            setSessions((current) => current.map((item) =>
                item.sessionRef === session.sessionRef
                    ? { ...item, status: "REVOKED" }
                    : item
            ));
            setActionMessage("Session revoked successfully.");
        } catch (error) {
            setActionError(error.response?.data?.message || "Unable to revoke this session.");
        } finally {
            setRevokingRef(null);
        }
    }, []);

    const activeCount = sessions.filter((session) => session.status === "ACTIVE").length;
    const revokedCount = sessions.filter((session) => session.status === "REVOKED").length;

    return (
        <main className="dashboard">
            <header className="dashboard-header">
                <div>
                    <p className="eyebrow">ZEROPULSE / SECURITY</p>
                    <h1>Security Dashboard</h1>
                    <p className="muted">Monitor active sessions and recent security activity.</p>
                </div>
                <div className="header-actions">
                    <span className={`connection-status connection-${socketStatus}`}>
                        <span className="connection-dot" />
                        Socket {socketStatus}
                    </span>
                    <button className="button button-secondary" type="button" onClick={onLogout}>
                        Log out
                    </button>
                </div>
            </header>

            <section className="summary-grid" aria-label="Session summary">
                <article className="summary-card">
                    <span>Active Sessions</span>
                    <strong>{sessionsLoading ? "—" : activeCount}</strong>
                </article>
                <article className="summary-card">
                    <span>Revoked Sessions</span>
                    <strong>{sessionsLoading ? "—" : revokedCount}</strong>
                </article>
                <article className="summary-card">
                    <span>Recent Threat Events</span>
                    <strong>{eventsLoading ? "—" : events.length}</strong>
                </article>
            </section>

            <section className="panel">
                <div className="panel-heading">
                    <div>
                        <p className="eyebrow">ACCESS CONTROL</p>
                        <h2>Active Sessions</h2>
                    </div>
                </div>
                {actionMessage && <p className="feedback success" role="status">{actionMessage}</p>}
                {actionError && <p className="feedback error" role="alert">{actionError}</p>}
                {sessionsLoading ? <p className="empty-state">Loading sessions…</p> :
                    sessionsError ? <p className="feedback error" role="alert">{sessionsError}</p> :
                        sessions.length === 0 ? <p className="empty-state">No sessions found.</p> : (
                            <div className="table-scroll">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Device Information</th>
                                            <th>Device ID</th>
                                            <th>Login Time</th>
                                            <th>Status</th>
                                            <th><span className="sr-only">Action</span></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {sessions.map((session) => (
                                            <tr key={session.sessionRef}>
                                                <td>{session.ipAddress || "Unknown"}</td>
                                                <td className="device-info">{session.deviceInfo || "Unknown"}</td>
                                                <td>{session.deviceId || "—"}</td>
                                                <td>{formatDate(session.loginTime)}</td>
                                                <td><StatusBadge status={session.status} /></td>
                                                <td>
                                                    <button
                                                        className="button button-danger"
                                                        type="button"
                                                        disabled={session.status !== "ACTIVE" || revokingRef === session.sessionRef}
                                                        onClick={() => killSession(session)}
                                                    >
                                                        {revokingRef === session.sessionRef ? "Revoking…" : "Kill Session"}
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
            </section>

            <section className="panel">
                <div className="panel-heading">
                    <div>
                        <p className="eyebrow">CONTINUOUS EVALUATION</p>
                        <h2>Threat Event Log</h2>
                    </div>
                </div>
                {eventsLoading ? <p className="empty-state">Loading threat events…</p> :
                    eventsError ? <p className="feedback error" role="alert">{eventsError}</p> :
                        events.length === 0 ? <p className="empty-state">No threat events recorded.</p> : (
                            <div className="table-scroll">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Event Type</th>
                                            <th>Severity</th>
                                            <th>Risk Score</th>
                                            <th>Timestamp</th>
                                            <th>Session</th>
                                            <th>Processing</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {events.map((event) => (
                                            <tr key={eventKey(event)}>
                                                <td>{event.type || "Unknown"}</td>
                                                <td><SeverityBadge severity={event.severity} /></td>
                                                <td>{Number.isFinite(event.riskScore) ? event.riskScore : "—"}</td>
                                                <td>{formatDate(event.timestamp)}</td>
                                                <td>{event.sessionRef || "—"}</td>
                                                <td>{(event.processingStatus || "unknown").replaceAll("_", " ")}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
            </section>
        </main>
    );
}
