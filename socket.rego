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

allowed_ports := {8000, 8080}
allowed_commands := {"curl", "python3"}

allow = {
	"mtls": true,
	"permissive": false,
} {
	allowed_ports[input.port]
	allowed_commands[input.command]
}
