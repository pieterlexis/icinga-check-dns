# check_dns.py - Check your zone's DNSSEC

This check script for Icinga and Nagios uses [dnsviz](https://github.com/dnsviz/dnsviz) (the Python part, not the webservice) to check a zone's DNSSEC status.

## Installation

The plugin can be installed from PyPI using the `pip` command. It is highly recommended to use a virtual environment for installation:

```
export CHECK_DNS_PATH=/opt/check-dns/
mkdir $CHECK_DNS_PATH
python3 -m venv $CHECK_DNS_PATH/venv
$CHECK_DNS_PATH/venv/bin/python3 -m pip install --upgrade pip
$CHECK_DNS_PATH/venv/bin/python3 -m pip install icinga-check-dns
```

After installing, the plugin is available under the path `$CHECK_DNS_PATH/venv/bin/check_dns.py` for use with the monitoring tool of your choice.

## License

GPLv2
