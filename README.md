# kisskissie
Simple proof of concept eXternal Xml Entity (XXE) scan and exfiltrate tool.

Still needs lots of work to get to a usable version.
The tool works by starting two network services on the attackers host, one for serving a DTD file and another for collecting the final exfiltrate data from the victim.
The tool looks for a scan template which the user should customize for their victim and a list of files that will be attempted for exfiltration.

TODO: Add more builting attack templates.
Add fuzzing capabilities.
Move code into classes and general clean up.
