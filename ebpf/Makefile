CC = clang
DEVICE = $(shell ls /sys/class/net | head -1)

buildxdp: xdp_pass_kern.o
	$(CC) -O2 -g -Wall -target bpf -c xdp_pass_kern.bpf.c -o xdp_pass_kern.bpf.o -I/usr/include/aarch64-linux-gnu/

loadxdp: unloadxdp
	sudo ip link set dev $(DEVICE) xdpgeneric obj xdp_pass_kern.bpf.o sec xdp

unloadxdp:
	sudo ip link set $(DEVICE) xdpgeneric off

createmap:
	sudo bpftool map create /sys/fs/bpf/xdp_stats_map type percpu_hash key 2 value 64 entries 64 name xdp_stats_map
	sudo bpftool map create /sys/fs/bpf/xdp_opa_input_map type percpu_array key 4 value 256 entries 1 name xdp_opa_input_map

deletemap:
	sudo rm /sys/fs/bpf/xdp_stats_map
	sudo rm /sys/fs/bpf/xdp_opa_input_map

dumpmap:
	sudo bpftool map dump name xdp_stats_map

logs:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm *.o
