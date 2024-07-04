class SocketService {
    static connection(socket) {
        console.log("Client connection established", socket.id);
        socket.on("disconnect", function () {
            console.log("Client disconnected successfully.");
        });
    }
}

export default SocketService;
