#
# Regular cron jobs for the camblet-driver package.
#
0 4	* * *	root	[ -x /usr/bin/camblet-driver_maintenance ] && /usr/bin/camblet-driver_maintenance
