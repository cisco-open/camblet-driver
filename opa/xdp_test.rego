package xdp
import future.keywords

test_post_allowed if {
    allow with input as {"protocol": ETH_P_IP}
}
