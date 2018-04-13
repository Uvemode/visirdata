#!/usr/bin/python3
import re
import sys 
import json
import requests
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plot
import operator

def rm_adm_ips(log_file, filtered_log):
    adm_ips = []
    with open(log_file, "r") as fd:
        with open("apache_filter.log", "w") as od:
            lines = fd.readlines()
            for line in lines:
                for ip in adm_ips:
                    if not any(ip in line for ip in adm_ips):
                        od.write(line)                    

def make_autopct(values):
    def my_autopct(pct):
        total = sum(values)
        val = int(round(pct*total/100.0))
        return '{p:.1f}%  ({v:d})'.format(p=pct,v=val)
    return my_autopct

def plot_fig(top, title, img, nest1=None, nest2=None):
    top_10 = sorted(top.items(), key=operator.itemgetter(1), reverse=True)
    top_10 = top_10[:10]   
    explode = []
    labels = []
    values = []
    if nest1 and nest2:    
        nest = []
        nest_colors = ['#62DC64','#DC2839']
        for label, value in top_10:
            explode.append(0.05)
            labels.append(label)
            values.append(value)
            if label in nest1:
                nest.append(nest1[label])
            else:
                nest.append(0)
            if label in nest2:
                nest.append(nest2[label])
            else:
                nest.append(0)
    else:
        for label, value in top_10:
            explode.append(0.05)
            labels.append(label)
            values.append(value)

    colors = ['#66b3ff', "gold", '#80f9ad', '#ff6666', '#8af1fe',"#4984b8", "#FD961F", "yellowgreen", "#ac4f06", "#c48efd"]
    font = {'weight' : 'bold',
            'size'   : 14}
    plot.rc('font', **font)
    fig1, ax1 = plot.subplots()
    patches, text, porc = plot.pie(values, autopct=make_autopct(values), colors=colors, shadow=False, startangle=90)
    if nest1 and nest2:
        plot.pie(nest, colors=nest_colors, radius=0.75, startangle=90)
        centre_circle = plot.Circle((0,0),0.5, color='black', fc='white',linewidth=0)
    else:
        centre_circle = plot.Circle((0,0),0.70,fc='white')
    plot.legend(patches, labels, loc="best")
    fig = plot.gcf()
    fig.gca().add_artist(centre_circle)
    ax1.set_title(title, fontweight = 'bold')
    ax1.axis('equal')  
    plot.tight_layout()
    plot.savefig("{}.png".format(img), dpi=199)
    print("{}.png".format(img))

def fill_ipcountry_data(ip, ip_count, ip_country):
    if ip not in ip_count:
        ip_count[ip] = 1
    else:
        ip_count[ip] += 1
    if ip not in ip_country:
        url = "http://freegeoip.net/json/" + ip
        res = requests.get(url)
        content = res.content.decode("utf8")
        json_res = json.loads(content)
        country = json_res["country_name"]
        ip_country[ip] = country

def fill_usr_data(line, ip, ip_failed, ip_success, user_count, user_failed, user_success):
    match = re.search(r'Failed password.*'+re.escape(ip), line)
    if match:
        if ip not in ip_failed:
            ip_failed[ip] = 1
        else:
            ip_failed[ip] += 1
        user_parse = re.search(r'for (?:invalid user\s)?(.*?)\sfrom', match.group(0))
        if user_parse:
            user = user_parse.group(1)
            if user not in user_count:
                user_count[user] = 1
            else:
                user_count[user] += 1
            if user not in user_failed:
                user_failed[user] = 1
            else:
                user_failed[user] += 1
    match = re.search(r'Accepted.*'+re.escape(ip), line)
    if match:
        if ip not in ip_success:
            ip_success[ip] = 1
        else:
            ip_success[ip] += 1
        user_parse = re.search(r'password for .* from', match.group(0))
        if user_parse:
            user = user_parse.group(0).replace("password for ", "")
            user = user.replace(" from", "")
            if user not in user_count:
                user_count[user] = 1
            else:
                user_count[user] += 1
            if user not in user_success:
                user_success[user] = 1
            else:
                user_success[user] += 1

def fill_country_data(ip_count, ip_country, country_count):
    for ip, country in ip_country.items():
        if country not in country_count:
            country_count[country] = ip_count[ip]
        else:
            country_count[country] += ip_count[ip]

def main():
    nlines = 0
    ip_count = {}
    ip_success = {}
    ip_failed = {}
    ip_lockout = {}
    user_count = {}
    user_success = {}
    user_failed = {}
    ip_country = {}
    country_count = {}
    log_file = sys.argv[1]
    filtered_log = "apache_filter.log"
    log_type = "default"

    rm_adm_ips(log_file, filtered_log)

    with open(filtered_log, "r") as fd:
        line = fd.readline()
        match = re.search(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} - - ', line)
        if match:
            log_type = "apache"
        match = re.search(r'\S{3} \d{2} \d{2}:\d{2}:\d{2}', line)
        if match:
            log_type = "ssh"

    with open(filtered_log, "r") as fd:
        lines = fd.readlines()
        for line in lines:
            nlines += 1
            if log_type == "ssh":
                match = re.search(r'for.*from \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', line)
            elif log_type == "apache":
                match = re.match(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', line)
            if match:
                ip = re.search(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', match.group(0)).group(0)
                fill_ipcountry_data(ip, ip_count, ip_country)
                if log_type == "ssh":
                    fill_usr_data(line, ip, ip_failed, ip_success, user_count, user_failed, user_success)
            if log_type == "ssh":
                match = re.search(r'PAM.*rhost=\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', line)
                if match:
                    ip = re.search(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', match.group(0)).group(0)
                    if ip not in ip_lockout:
                        ip_lockout[ip] = 1
                    else:
                        ip_lockout[ip] += 1
    fill_country_data(ip_count, ip_country, country_count)
    if log_type == "ssh":
        plot_fig(ip_count, "Top 10 IPs", "sship")
        plot_fig(country_count, "Top 10 Countries", "sshcountry")
        plot_fig(user_count, "Top 10 Users", "sshusers", user_success, user_failed)
    elif log_type == "apache":
        plot_fig(ip_count, "Top 10 IPs", "apacheip")
        plot_fig(country_count, "Top 10 Countries", "apachecountry")

main()
