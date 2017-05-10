# log_template

Python 3 template for writing a script that parses log files using regular expressions

## Get Started

Examples:
* First ssh into server and substitute user to user
* Next cd /usr/app/application-dates/logs
* Then specify the compiled version of Python 3 and script
* ~/python3/bin/python3 gzaapps_stats.py

    To show options for using the script:
    $ ~/python3/bin/python3 gzaapps_stats.py --help
    
    Gather details for a particular user:
    $ ~/python3/bin/python3 gzaapps_stats.py --name Brennan
    
    Specify fields you don't wish to display 
    $ ~/python3/bin/python3 gzaapps_stats.py --dnr ip time uri
    
    Exclude specified query types from the report:
    $ ~/python3/bin/python3 gzaapps_stats.py --exclude 127.0.0.1

    Show requests that returned 400 responses:
    $ ~/python3/bin/python3 gzaapps_stats.py

