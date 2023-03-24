package xdp
import future.keywords

test_post_allowed if {
    allow with input as {"proto": ETH_P_IPV4}
}
