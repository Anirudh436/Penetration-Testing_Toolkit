***Penetration Testing Toolkit using Python***

*COMPANY* : CODTECH IT SOLUTIONS

*NAME* : ANIRUDH ANILKUMAR

*INTERN ID* :  CT08VAI

*DOMAIN* : CYBER SECURITY AND ETHICAL HACKING

*DURATION* : 4 WEEKS

*MENTOR* : NEELA SANTHOSH

***DESCRIPTION:***

The Penetration Testing Toolkit is a comprehensive, modular, and user-friendly application designed to simulate real-world attacks and help security professionals assess system vulnerabilities. Built entirely in Python, the toolkit combines a variety of modules—ranging from basic reconnaissance to advanced vulnerability scanning and exploitation—to provide a robust framework for ethical hacking and penetration testing. The application features a graphical user interface (GUI) based on Tkinter, making it accessible even to users who are less comfortable with command-line tools. With support for multi-threading and safe GUI updates, this toolkit ensures efficient, non-blocking operation during scans and tests.

***COMPONENTS:***

1. **Port Scanning**:
The Port Scanning module performs network port scans to discover open ports on a target host. It simulates the functionality of industry-standard tools like Nmap, helping testers identify potential entry points for further exploitation.

It uses the *socket* library to establish connections with the target host and the *threading* library to perform multi-threaded scans.It safely updates the GUI using `after()` and `winfo_exists()` to prevent the window from freezing during scans. It also provides real time log updates on open ports.


2. **Whois Lookup**:
This module retrieves detailed domain registration information by performing WHOIS queries. It can provide valuable insights, including registrar information, creation and expiration dates, and contact details.

This module utilizes the `whois` Python library to fetch domain details.
It also runs the lookup operation in a separate thread to maintain a responsive GUI.
It displays real-time status updates and results within the GUI.


3. **Subdomain Enumeration**:
The Subdomain Enumeration module discovers subdomains associated with a target domain, which is essential for mapping an organization's online presence and identifying potential attack surfaces.

This module leverages public Certificate Transparency logs (e.g., crt.sh) or custom wordlists to identify subdomains.
It also parses JSON responses and resolves subdomains to their IP addresses.
It implements multi-threading to improve the speed of the enumeration process.
It also handles rate limiting and error scenarios gracefully, providing useful feedback in the GUI.


4. **Banner Grabbing**:
Banner Grabbing helps identify the services running on open ports by retrieving and analyzing the banners that many network services send upon connection. This information can reveal software versions and configurations.

This module uses raw socket programming to connect to target services and capture banner data.
It applies timeouts and error handling to manage non-responsive services.
It then updates the GUI dynamically to display each retrieved banner, facilitating quick identification of potential vulnerabilities.


5. **CVE Lookup**:
The CVE Lookup module allows testers to query the National Vulnerability Database (NVD) using CVE IDs. It fetches detailed information about known vulnerabilities, including descriptions, severity ratings, and exploitability metrics.

It integrates with the NVD API to retrieve vulnerability details.
It processes JSON responses and extracts key metrics such as CVSS scores.
It runs asynchronously to avoid blocking the GUI, ensuring that results are displayed in real time.


6. **Brute Force Attack**:
This module simulates brute force attacks against login interfaces by systematically trying different password combinations until valid credentials are found. It is used to test the strength of authentication mechanisms.

It generates password combinations using Python’s `itertools`.
It also supports multi-threading to accelerate the attack while maintaining responsiveness.
It incorporates a user-controlled stop mechanism to abort the attack if needed.

7. **Packet Sniffer**:
The Packet Sniffer module captures and analyzes network traffic, enabling testers to monitor data flows between hosts. This can reveal sensitive information being transmitted in cleartext, as well as details about network configuration and active connections.

It uses raw sockets on Linux or Scapy for cross-platform compatibility.
It parses Ethernet, IP, TCP, and UDP headers to extract and display network details.
It operates in a separate thread to continuously capture packets without impacting GUI performance.
It includes a user-controlled stop mechanism to cease packet capture when desired.


***Steps for Testing***:
-Ensure Python 3.6+ is installed in the system.
-Install required libraries by running `pip install -r requirements.txt` in the terminal.
-Run the GUI application using `python main.py` in the terminal.
-Select the desired module from the GUI and follow the on-screen instructions to configure and execute the test

*Port Scanning*:

- Enter target URL(like `scanme.nmap.org`), and start the scan.

-Verify that the output displays a list of open ports and updates in real time.

*WHOIS Lookup*:

- Input a domain (e.g., `example.com`) and execute the lookup.

- Confirm that the output displays the domain’s WHOIS information, including registrant details and contact information

*Subdomain Enumeration*:

-Use a target domain with known subdomains.

-Check that the module correctly identifies and resolves subdomains.

*Banner Grabbing*:

- Provide a target IP and initiate banner grabbing.

- Ensure that service banners are retrieved and logged accurately.

*CVE Lookup*:

- Input a valid CVE ID (e.g., `CVE-2023-23397`) and perform a lookup.

- Validate that detailed vulnerability information is shown.

*Brute Force Attack*:

- Set up a controlled environment (like a local web app) to test login mechanisms.

- Start the attack, monitor the logs, and use the stop feature if necessary.

*Packet Sniffer*:

- Begin packet capture and monitor the network traffic.

- Verify that key packet details (IP addresses, protocols, etc.) are displayed.

***OUTPUT***:
![Image](https://github.com/user-attachments/assets/f4bd4830-c602-4fcd-8bd7-f7e36f803040)
![Image](https://github.com/user-attachments/assets/42240933-c126-4f1a-8493-6ef6319bde1c)
![Image](https://github.com/user-attachments/assets/0feb0dcb-1748-40c7-83af-89b572934215)
![Image](https://github.com/user-attachments/assets/c4841b8b-1761-4fbc-8c82-63ab0ba742b2)
![Image](https://github.com/user-attachments/assets/72ec41f9-2109-4e9c-968b-5e85e2033f58)
![Image](https://github.com/user-attachments/assets/0bc1d824-f365-4752-8571-c9513c5f14b8)
![Image](https://github.com/user-attachments/assets/f8088319-0811-4b98-a5b9-f1791900df30)

***FINAL THOUGHTS***:

This toolkit serves as a solid foundation for penetration testing, whether for learning, internal security testing, or ethical hacking. It strikes a balance between functionality, ease of use, and expandability, making it a great choice for both beginners and experienced testers.
