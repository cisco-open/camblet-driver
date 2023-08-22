package socket

allowed_ports := {8000, 8080}

allowed_commands := {"curl", "python3"}

allow {
	allowed_ports[input.port]

	allowed_commands[input.command]
}
