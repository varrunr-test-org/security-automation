"""
Parses dependency check result and notifies the SLACK_WEBHOOK_URL at the given channel

"""
import json
import sys
import requests

f = open(sys.argv[1], "r")
json_str = f.read()

json_dict = json.loads(json_str)

def _get_divider_section():
    return	"""
            {
                "type": "divider"
            }
        """

def _get_title_section(num_cve):
    return """
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*%s* new CVEs found"
			}
        } """ % num_cve

def _get_cve_section(cve, severity, score):
    return """
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*<https://nvd.nist.gov/vuln/detail/%s|%s>*\\n*Severity* : %s\\n *CVSS V2*: %s\\n"
                }
            }
        """ % (cve, cve, severity, score)

def _get_desc_section(description):
    return """
		{
			"type": "context",
			"elements": [
				{
					"type": "plain_text",
					"emoji": true,
					"text": "%s"
				}
			]
		}
        """ % description


dependencies = None
if 'dependencies' in json_dict.keys():
    dependencies = json_dict['dependencies']

cves = []
for dependency in dependencies:
    vulnerabilities = None
    if 'vulnerabilities' in dependency.keys():
        vulnerabilities = dependency['vulnerabilities']

    if vulnerabilities is None:
        continue

    for vuln in vulnerabilities:
        cves.append(vuln)

slack_message = ""
if (len(cves) > 0):
    cve_section = ""
    for i in range(0, len(cves)):
        cve_section = cve_section +\
                      _get_cve_section(cves[i]['name'], cves[i]['severity'], cves[i]['cvssv2']['score']) \
                      + "," +_get_desc_section(cves[i]['description']);
        if i != len(cves) - 1:
            cve_section += ","

    slack_message = """{
        "channel": "#test-dependency-check-slack",
        "blocks": [ %s, %s, %s, %s ] 
    }""" % (_get_title_section(len(cves)),
           _get_divider_section(),
           cve_section,
           _get_divider_section())

    form_data = {'payload' : slack_message}
    if len(sys.argv) == 3:
        resp = requests.post(sys.argv[2], data=form_data)
        if resp.status_code != 200:
            sys.exit(1)






