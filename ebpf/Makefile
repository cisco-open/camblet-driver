CC = clang

buildxdp: xdp_pass_kern.o
	$(CC) -O2 -target bpf -c xdp_pass_kern.c -o xdp_pass_kern.o

loadxdp: unloadxdp
	sudo ip link set dev lo xdpgeneric obj xdp_pass_kern.o sec xdp

unloadxdp:
	sudo ip link set lo xdpgeneric off

createmap:
	sudo bpftool map create /sys/fs/bpf/xdp_stats_map type percpu_hash key 2 value 64 entries 64 name xdp_stats_map

logs:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm *.o
