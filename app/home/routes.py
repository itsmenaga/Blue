from app.home import blueprint
from flask import Flask, render_template, request, redirect, json
from flask_login import login_required
from Wappalyzer import Wappalyzer, WebPage
import requests
from spyse import spyse
from bs4 import BeautifulSoup
import cfscrape

s = spyse()

def get_subdomains(target, param, page, raw=False):
    retval = ""
    data = s.subdomains_aggregate(target, param=param, page=page)['cidr']
    keys = data.keys()
    for key in keys:
        domains = data[key]['results']
        for d in domains:
            domain = d['data']['domains']
            if len(domain) > 1:
                for i in domain:
                    retval += "{}\n".format(i)
                else:
                    retval += "{}\n".format(domain[0])
    return retval

def get_dns_ptr(target, param, page, raw=False):
    data = s.dns_ptr(target, param=param, page=1)
    print(data)
    retval = ""
    for record in data['records']:
        retval += "PTR RECORD @ {} FROM HOSTNAME {}\n".format(
        record['ip']['ip'],
        record['hostname']
        )
    return retval


def get_dns_soa(target, param, page, raw=False):
    data = s.dns_soa(target, param=param, page=1)
    retval = ""
    for record in data['records']:
        retval += "SOA RECORD @ {} FROM {} WITH SERIAL {}\n".format(
        record['domain']['domain'],
        record['domain']['ip']['ip'],
        record['serial']
        )
    return retval

def get_dns_mx(target, param, page, raw=False):
    data = s.dns_mx(target, param=param, page=1)
    retval = ""
    for record in data['records']:
        retval += "MX RECORD @ {} FROM IP {}\n".format(
        record['mx_domain']['domain'],
        record['mx_domain']['ip']['ip']
        )
    return retval

def get_dns_aaaa(target, param, page, raw=False):
    data = s.dns_aaaa(target, param=param, page=1)
    retval = ""
    for record in data['records']:
        retval += "AAAA RECORD @ {} FROM IP {}\n".format(
        record['domain']['domain'],
        record['ipv6']
        )
    return retval

def get_dns_ns(target, param, page, raw=False):
    data = s.dns_ns(target, param=param, page=1)
    retval = ""
    for record in data['records']:
        retval += "NS RECORD @ {} FROM {}\n".format(
        record['ns_domain']['domain'],
        record['ns_domain']['ip']['ip']
        )
    return retval

def get_dns_a(target, param, page, raw=False):
    data = s.dns_a(target, param=param, page=1)
    retval = ""
    for record in data['records']:
        retval += "A RECORD @ {} FROM {}\n".format(
        record['domain']['domain'],
        record['ip']['ip']
        )
    return retval

def get_dns_txt(target, param, page, raw=False):
	data = s.dns_txt(target, param=param, page=1)
	retval = "TXT RECORDS FROM {}\n".format(target)
	for record in data['records']:
		retval += '> {}\n'.format(record['data'])
	return retval

def get_dns_all(target, param, raw=False):
    data = ""
    data += get_dns_ptr(target, param=param, page=None)
    data += get_dns_soa(target, param=param, page=None)
    data += get_dns_mx(target, param=param, page=None)
    data += get_dns_aaaa(target, param=param, page=None)
    data += get_dns_a(target, param=param, page=None)
    data += get_dns_ns(target, param=param, page=None)
    data += get_dns_txt(target, param=param, page=None)
    return data

def get_domains_on_ip(target, param, page, raw=False):
    retval = ""
    data = s.domains_on_ip(target, param=param, page=page)
    for record in data['records']:
        retval += "{}\n".format(record['domain'])
    return retval

@blueprint.route('/index')
@login_required
def index():
    return render_template('index.html')


@blueprint.route('/<template>')
@login_required
def route_template(template):
    return render_template(template + '.html')

@blueprint.route("/detection", methods=['GET', 'POST'])
@login_required
def wappalyzer_detection(): # pretty print the output (set; need to change to dict)
    target = ""
    if request.form.get('target'):
        target = request.form.get('target')
        req = requests.get('http://' + target)
        if req.status_code == 200:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url('https://' + target)
            output = wappalyzer.analyze(webpage)

            return render_template('detection.html', target=output)
        else:
           req = requests.get('https://' + target)
           wappalyzer = Wappalyzer.latest()
           webpage = WebPage.new_from_url('https://' + target)
           output = wappalyzer.analyze(webpage)

        return render_template('detection.html', target=output)

    else:
        return render_template('detection.html')

@blueprint.route("/subdomains", methods=['GET', 'POST'])
@login_required
def lookup():
    if request.method == 'POST':
        target = ""
        if request.form.get('target'):
            target = request.form.get('target')
            s = spyse()
            retval = ""
            data = s.subdomains_aggregate(target, param='domain', page=1)['cidr']
            keys = data.keys()

            for key in keys:
                domains = data[key]['results']
                for d in domains:
                    domain = d['data']['domains']
                    if len(domain) > 1:
                        for i in domain:
                            retval += "{}\n".format(i)
                        else:
                            retval += "{}\n".format(domain[0])
        return render_template('subdomains.html', target=retval)

    else:
        return render_template('subdomains.html')

@blueprint.route("/emails", methods=['GET', 'POST'])
@login_required
def hunterio_search():
    hunterapikey = "your_api_key"
    target = ""
    if request.form.get('target'):
        target = request.form.get('target')
        try:
            lookup = requests.get("https://api.hunter.io/v2/domain-search?domain=" + target + "&api_key=" + hunterapikey)
            jsonresponse = json.loads(lookup.content)
            emails = []

            if str(jsonresponse['data']['webmail']) == 'True':
                mail = 'This is a webmail service, and therefore cannot disclose email addresses.'
                print(jsonresponse['data']['webmail'])
            else:
                for email in jsonresponse['data']['emails']:
                    emails.append(email['value'] + "\n")

                e = [str(i) for i in emails]
                mail = str("".join(e))
                i = 0
        except:
            mail = "Something went wrong..."
        return render_template('emails.html', target=mail)
    else:
        return render_template('emails.html')


@blueprint.route("/dork", methods=['GET', 'POST'])
@login_required
def google_dork():
    target = ""
    if request.form.get('target'):
        target = request.form.get('target')
        location = "https://www.google.com/search?q=site:" + target + " ext:php OR ext:asp OR ext:aspx OR ext:txt OR ext:sql OR ext:bak OR ext:csv OR ext:xml"
        if len(target) > 1:
            return redirect(location, code=302)
        elif len(target) >0:
            return render_template('dork.html')
    else:
        return render_template('dork.html')

@blueprint.route("/lookup", methods=['GET', 'POST'])
@login_required
def leak_lookup():
    target = ""
    if request.form.get('target'):
        target = request.form.get('target')
        scraper = cfscrape.create_scraper() ## to bypass the 5 sec shit
        result = scraper.get("https://weleakinfo.com/search?type=email&query=*@" + target + "&wildcard=true")
        src = result.content

        soup = BeautifulSoup(src, 'html.parser')
        for output in soup.find_all('h1')[1]:
            if output == "$70":
                output = "An error has occurred. No results found, or too many. Did you typo the domain?"
                return render_template('lookup.html', target=output)

            else:
                return render_template('lookup.html', target=output)

    else:
        return render_template('lookup.html')
