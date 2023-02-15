package xdp
import future.keywords

test_post_allowed if {
    allow with input as {"type": "udp"}
}
