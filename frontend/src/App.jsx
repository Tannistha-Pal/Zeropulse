import { useCallback, useEffect, useRef, useState } from "react";
import api from "./api";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import { SocketProvider } from "./SocketContext";
import "./App.css";

const REVOCATION_FALLBACK = "Your session was revoked for security reasons.";

function App() {
    const [token, setToken] = useState(() => localStorage.getItem("token"));
    const [pathname, setPathname] = useState(() =>
        localStorage.getItem("token") ? "/dashboard" : "/login"
    );
    const [securityAlert, setSecurityAlert] = useState("");
    const [logoutError, setLogoutError] = useState("");
    const handledRevocation = useRef(false);
    const intentionalLogout = useRef(false);

    const navigate = useCallback((path, replace = false) => {
        if (replace) {
            window.history.replaceState({}, "", path);
        } else {
            window.history.pushState({}, "", path);
        }
        setPathname(path);
    }, []);

    useEffect(() => {
        const handlePopState = () => {
            const authenticatedPath = localStorage.getItem("token")
                ? (window.location.pathname === "/login" ? "/dashboard" : window.location.pathname)
                : "/login";
            setPathname(authenticatedPath);
        };
        window.addEventListener("popstate", handlePopState);
        if (window.location.pathname !== pathname) {
            window.history.replaceState({}, "", pathname);
        }
        return () => window.removeEventListener("popstate", handlePopState);
    }, [pathname]);

    const handleLogin = useCallback((newToken) => {
        localStorage.setItem("token", newToken);
        handledRevocation.current = false;
        intentionalLogout.current = false;
        setSecurityAlert("");
        setLogoutError("");
        setToken(newToken);
        navigate("/dashboard", true);
    }, [navigate]);

    const handleSessionRevoked = useCallback((notification) => {
        if (
            notification?.action !== "REVOKE" ||
            typeof notification.sessionRef !== "string" ||
            !notification.sessionRef ||
            handledRevocation.current
        ) {
            return;
        }

        if (!intentionalLogout.current) {
            handledRevocation.current = true;
            const reason = typeof notification.reason === "string"
                ? notification.reason.trim().slice(0, 300)
                : "";
            setSecurityAlert(reason || REVOCATION_FALLBACK);
        }
        localStorage.removeItem("token");
        setToken(null);
        navigate("/login", true);
    }, [navigate]);

    const handleLogout = useCallback(async () => {
        intentionalLogout.current = true;
        setLogoutError("");
        try {
            await api.post("/auth/revoke-session");
        } catch (error) {
            setLogoutError(
                error.response?.data?.message ||
                "The session could not be revoked on the server. You have been signed out locally."
            );
        } finally {
            localStorage.removeItem("token");
            setToken(null);
            setSecurityAlert("");
            navigate("/login", true);
            intentionalLogout.current = false;
        }
    }, [navigate]);

    const dismissSecurityAlert = useCallback(() => setSecurityAlert(""), []);

    return (
        <div className="app-shell">
            {token && pathname === "/dashboard" ? (
                <SocketProvider token={token} onSessionRevoked={handleSessionRevoked}>
                    <Dashboard onLogout={handleLogout} />
                </SocketProvider>
            ) : (
                <Login onLogin={handleLogin} logoutError={logoutError} />
            )}
            {securityAlert && (
                <div className="modal-backdrop">
                    <section
                        className="security-modal"
                        role="alertdialog"
                        aria-modal="true"
                        aria-labelledby="security-alert-title"
                        aria-describedby="security-alert-reason"
                    >
                        <div className="modal-icon" aria-hidden="true">!</div>
                        <p className="eyebrow">SECURITY NOTICE</p>
                        <h2 id="security-alert-title">Session terminated</h2>
                        <p id="security-alert-reason">{securityAlert}</p>
                        <button className="button button-primary" type="button" onClick={dismissSecurityAlert}>
                            Continue to login
                        </button>
                    </section>
                </div>
            )}
        </div>
    );
}

export default App;
