# visirdata
Python script that I coded for practicing with charts. It allows to visualize apache and ssh log files in pie charts plots.

It also filters the IP addresses of your choice out of the output image, just in case this may expose the admins address. For this, edit the **adms_ips** list at **rm_amds_ips()** function.

You can also use the "script" (like 4 lines...) merge_logs.sh to merge apache logs in one file called apache.log.

Usage: visirdata.py [logfile]






![apachecountry](https://user-images.githubusercontent.com/18345040/52536062-299b6d00-2d56-11e9-8452-a40bdb3d21ad.png)
![sshusers](https://user-images.githubusercontent.com/18345040/52536085-4cc61c80-2d56-11e9-8fc9-0f01aace7443.png)
