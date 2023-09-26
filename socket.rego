package socket

# the scheme of the input object is the following:
# {
#   "port": 8000,
#   "command": "curl",
#   "uid": 501,
#   "direction": 0
# }

# direction constants
INPUT := 0
OUTPUT := 1

allowed_ports := {8000, 8080, 5001}

allowed_commands := {
	"curl",
	"python3",
	"file-server",
	"nginx",
	"iperf",
}

allow = {
	"mtls": true,
	"permissive": false,
} {
	allowed_ports[input.port]
	allowed_commands[input.command]
}

# to test that our bearssl server is compatible with non-bearssl clients
allow = {
	"mtls": false,
	"permissive": false,
} {
	input.port == 7000
	input.command == "python3"
}

# Allow all traffic from the host curl to container nginx through docker-proxy.
# From docker-proxy to nginx, we don't repackage the traffic again, mTLS is
# flowing through the docker-proxy transparently. The most importnatn thing is
# that nginx thinks that it listens on port 80, and we have to write the rule for that.
allow = {
	"mtls": true,
	"permissive": false,
} {
	input.direction == OUTPUT
	input.port == 8080
	input.command == "curl"
}

allow = {
	"mtls": true,
	"permissive": false,
} {
	input.direction == INPUT
	input.port == 80
	input.command == "nginx"
}
