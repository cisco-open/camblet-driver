#
# Regular cron jobs for the nasp-kernel-module package.
#
0 4	* * *	root	[ -x /usr/bin/nasp-kernel-module_maintenance ] && /usr/bin/nasp-kernel-module_maintenance
