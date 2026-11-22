import { useEffect, useMemo, useState } from "react";
import { io } from "socket.io-client";
import { SOCKET_URL } from "./api";
import { SocketContext } from "./socketContextValue";

export function SocketProvider({ token, onSessionRevoked, children }) {
    const socket = useMemo(() => io(SOCKET_URL, {
        auth: { token },
        autoConnect: false
    }), [token]);
    const [status, setStatus] = useState("connecting");

    useEffect(() => {
        const handleConnect = () => setStatus("connected");
        const handleDisconnect = () => setStatus("disconnected");
        const handleConnectionError = () => setStatus("disconnected");
        const handleSessionRevoked = (payload) => onSessionRevoked(payload);

        socket.on("connect", handleConnect);
        socket.on("disconnect", handleDisconnect);
        socket.on("connect_error", handleConnectionError);
        socket.on("session_revoked", handleSessionRevoked);
        socket.connect();

        return () => {
            socket.off("connect", handleConnect);
            socket.off("disconnect", handleDisconnect);
            socket.off("connect_error", handleConnectionError);
            socket.off("session_revoked", handleSessionRevoked);
            socket.disconnect();
        };
    }, [onSessionRevoked, socket]);

    return (
        <SocketContext.Provider value={{ socket, status }}>
            {children}
        </SocketContext.Provider>
    );
}
