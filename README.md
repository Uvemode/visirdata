# visirdata
Python script that allows to visualize apache and ssh log files in pie charts plots.

It also filters the IP addresses of your choice out of the output image, just in case this may expose the admins address. Check out the adms_ips list in rm_amds_ips() function.

You can also use the "script" (like 4 lines...) I offer to merge apache logs in one file called apache.log.

Usage: visirdata.py [logfile]
