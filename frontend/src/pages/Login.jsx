import { useState } from "react";
import api from "../api";

function Login({ onLogin, logoutError }) {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [loading, setLoading] = useState(false);

    const handleLogin = async (event) => {
        event.preventDefault();
        setMessage("");
        setLoading(true);

        try {
            const response = await api.post("/auth/login", { email, password });
            onLogin(response.data.token);
        } catch (error) {
            setMessage(
                error.response?.data?.message ||
                "Login failed. Please try again."
            );
        } finally {
            setLoading(false);
        }
    };

    return (
        <main className="login-page">
            <section className="login-card">
                <p className="eyebrow">CONTINUOUS ACCESS EVALUATION</p>
                <h1>ZeroPulse</h1>
                <p className="muted">Sign in to your security dashboard.</p>

                <form onSubmit={handleLogin}>
                    <label htmlFor="email">Email</label>
                    <input
                        id="email"
                        type="email"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        placeholder="you@example.com"
                        autoComplete="username"
                        required
                    />

                    <label htmlFor="password">Password</label>
                    <input
                        id="password"
                        type="password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        placeholder="Enter your password"
                        autoComplete="current-password"
                        required
                    />

                    <button className="button button-primary login-submit" type="submit" disabled={loading}>
                        {loading ? "Signing in…" : "Sign in"}
                    </button>
                </form>

                {message && <p className="feedback error" role="alert">{message}</p>}
                {logoutError && <p className="feedback error" role="alert">{logoutError}</p>}
            </section>
        </main>
    );
}

export default Login;
