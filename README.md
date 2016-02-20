# kisskissie
Simple proof of concept eXternal Xml Entity (XXE) scan and exfiltrate tool.

Still needs lots of work to get to a usable version.
The tool works by starting two network services on the attackers host, one for serving a DTD file and another for collecting the final exfiltrate data from the victim.
The tool looks for a scan template which the user should customize for their victim and a list of files that will be attempted for exfiltration.

TODO: Add more builtin attack templates.
Add fuzzing capabilities.
Move code into classes and general clean up.

## Authentication
HTTP basic authentication is supported by default. Use the `--auth-user` flag
to specify a username and you will be prompted for a password.

## Templates
Some applications may require custom templates files for the smasher if they
expect specific HTTP headers in the request or require a specific XML format.
These should be placed in templates/smasher; if you need to specify custom
headers, the filename should end in .http. For an example, see example.http in
this directory.

To specify a template, use the `--template` flag. For example:
```
python2 kisskissie.py [...] --template example.http https://vuln.example.com/xml_processor
```
