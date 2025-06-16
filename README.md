**LogWatcher** is a cybersecurity tool that scans log files for suspicious activity like repeated failed SSH login attempts and blacklisted IPs.

Features:
- Detects brute-force attempts based on time window and threshold
- Matches IPs against a blacklist
- Outputs suspicious IPs for further analysis

Requirements:

- Python 3.6+
- No external libraries

LogWatcher is a log analysis tool focused on security, especially useful for detecting suspicious behavior in log files, such as brute-force SSH attempts (multiple failed login attempts).

It reads a log file, searches for error entries (such as “Failed password from IP”), and identifies which IPs made multiple attempts within a short period of time. It also checks whether those IPs are present in a provided blacklist.
How It Works Internally:

    - Receives command-line arguments;

    - Loads the blacklist file (if it exists). If provided, it reads one IP per line and stores them in a set;

    - Extracts events from the log file;

    - Analyzes the events to detect suspicious behavior;

    - Prints the results to the console

Example:

Jun 16 15:10:01 ... from 192.168.1.10 ...
Jun 16 15:11:01 ... from 192.168.1.10 ...
Jun 16 15:12:01 ... from 192.168.1.10 ...
Jun 16 15:13:01 ... from 192.168.1.10 ...
Jun 16 15:14:01 ... from 192.168.1.10 ...

With threshold=5 and window=10, the program detects that IP 192.168.1.10 attempted access 5 times within less than 10 minutes and flags it as suspicious.
