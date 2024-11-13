# Introduction to Network Protocols

## Network Protocols

A set of used by two or more devices on a
network to descibe the order of data

## Transmission Control Protocol (TCP)

An internet communications protocol that
allows two devices to form a connection
and stream data. Please note that TCP isn't
limited to just limited to just two devices. It estabished a direct connection between two endpoints, but the underlying network infrastructure can handle can handle routing data packets across multiple devices.

## Address Resoultion Protocol (ARP)

A network protocol used to determine the MAC address of the next router ot device on the path. This ensures that that the data gets there. It also encrypts data using a protocol known as: SSL/TLS

## SSL/TLS

## Hyper Text Transfer Protocol Secure (HTTPS)

A network protocol that provides a secure method of communcation between clients and website servers.

## Domain Name System (DNS)

A network protocol that translates internet domain names into IP addresses.

## More on Network Protocols

## Simple Network Management Protocol (SNMP)
  
Is a network protocol used for monitoring and managing devices on a network.
SNMP can reset a password on a network device or change its baseline configuration.
It can also send requests to network devices for a report on how much of the network’s bandwidth is being used up. In the TCP/IP model, SNMP occurs at the application layer.

## Internet Control Message Protocol (ICMP)

Is an internet protocol used by devices to tell each other about data transmission errors across the network.
ICMP is used by a receiving device to send a report to the sending device about the data transmission. ICMP is
commonly used as a quick way to troubleshoot network connectivity and latency by issuing the “ping” command on a Linux operating system. In the TCP/IP model, ICMP occurs at the internet layer.

## Secure File Transfer Protocol (SFTP)

Is a secure protocol used to transfer files from one device to another over a network. SFTP uses secure shell (SSH),
typically through TCP port 22. SSH uses Advanced Encryption Standard (AES) and other types of encryption to ensure that unintended
recipients cannot intercept the transmissions. In the TCP/IP model, SFTP occurs at the application layer. SFTP is used often with
cloud storage. Every time a user uploads or downloads a file from cloud storage, the file is transferred using the SFTP protocol.

## How intrusions compromise your system

In this section of the course, you learned that every network has inherent vulnerabilities and could become the target of a network attack.

Attackers could have varying motivations for attacking your organization’s network. They may have financial, personal, or political motivations, or they may be a disgruntled employee or an activist who disagrees with the company's values and wants to harm an organization’s operations. Malicious actors can target any network. Security analysts must be constantly alert to potential vulnerabilities in their organization’s network and take quick action to mitigate them.

In this reading, you’ll learn about network interception attacks and backdoor attacks, and the possible impacts these attacks could have on an organization.
Network interception attacks

Network interception attacks work by intercepting network traffic and stealing valuable information or interfering with the transmission in some way.

Malicious actors can use hardware or software tools to capture and inspect data in transit. This is referred to as packet sniffing. In addition to seeing information that they are not entitled to, malicious actors can also intercept network traffic and alter it. These attacks can cause damage to an organization’s network by inserting malicious code modifications or altering the message and interrupting network operations. For example, an attacker can intercept a bank transfer and change the account receiving the funds to one that the attacker controls.

Later in this course you will learn more about malicious packet sniffing, and other types of network interception attacks: on-path attacks and replay attacks.
Backdoor attacks

A backdoor attack is another type of attack you will need to be aware of as a security analyst. An organization may have a lot of security measures in place, including cameras, biometric scans and access codes to keep employees from entering and exiting without being seen. However, an employee might work around the security measures by finding a backdoor to the building that is not as heavily monitored, allowing them to sneak out for the afternoon without being seen.

In cybersecurity, backdoors are weaknesses intentionally left by programmers or system and network administrators that bypass normal access control mechanisms. Backdoors are intended to help programmers conduct troubleshooting or administrative tasks. However, backdoors can also be installed by attackers after they’ve compromised an organization to ensure they have persistent access.

Once the hacker has entered an insecure network through a backdoor, they can cause extensive damage: installing malware, performing a denial of service (DoS) attack, stealing private information or changing other security settings that leaves the system vulnerable to other attacks. A DoS attack is an attack that targets a network or server and floods it with network traffic.
Possible impacts on an organization

As you’ve learned already, network attacks can have a significant negative impact on an organization. Let’s examine some potential consequences.

Financial: When a system is taken offline with a DoS attack or some other tactic, they prevent a company from performing  tasks that generate revenue. Depending on the size of an organization, interrupted operations can cost millions of dollars. Reparation costs to rebuild software infrastructure and to pay large sums associated with potential ransomware can be financially difficult. In addition, if a malicious actor gets access to the personal information of the company’s clients or customers, the company may face heavy litigation and settlement costs if customers seek legal recourse.

Reputation: Attacks can also have a negative impact on the reputation of an organization. If it becomes public knowledge that a company has experienced a cyber attack, the public may become concerned about the security practices of the organization. They may stop trusting the company with their personal information and choose a competitor to fulfill their needs.

Public safety: If an attack occurs on a government network, this can potentially impact the safety and welfare of the citizens of a country. In recent years, defense agencies across the globe are investing heavily in combating cyber warfare tactics. If a malicious actor gained access to a power grid, a public water system, or even a military defense communication system, the public could face physical harm due to a network intrusion attack.

### Key takeaways

Malicious actors are constantly looking for ways to exploit systems. They learn about new vulnerabilities as they arise and attempt to exploit every vulnerability in a system. Attackers leverage backdoor attack methods and network interception attacks to gain access to sensitive information they can use to exploit an organization or cause serious damage. These types of attacks can impact an organization financially, damage its reputation, and potentially put the public in danger.  It is important that security analysts stay educated in order to maintain network safety and reduce the likelihood and impact of these types of attacks. Securing networks has never been more important.

## DDOS

A distributed denial of service attack, or DDoS,
is a kind of DoS attack that uses
multiple devices or servers in
different locations to flood
the target network with unwanted traffic.
Use of numerous devices makes it more likely that
the total amount of traffic
sent will overwhelm the target server.
Remember, DoS stands for denial of service.
So it doesn't matter what part
of the network the attacker overloads;
if they overload anything, they win.
An unfortunate example I've
seen is an attacker who crafted
a very careful packet that caused
a router to spend extra time processing the request.
The overall traffic volume didn't overload the router;
the specifics within the packet did.

## ICMP Flood

An ICMP flood attack
is a type of DoS attack performed by an attacker
repeatedly sending ICMP packets to a network server.
This forces the server to send an ICMP packet.
This eventually uses up all the bandwidth for incoming
and outgoing traffic and causes the server to crash.
Both of the attacks we've discussed so far,
SYN flood and ICMP flood,
take advantage of communication protocols
by sending an overwhelming number of requests.
There are also attacks that can overwhelm
the server with one big request.
One example that we'll discuss
is called the ping of death.

## Ping of Death

A ping of death attack is
a type of DoS attack that is caused when a hacker
pings a system by sending it
an oversized ICMP packet
that is bigger than 64 kilobytes,
the maximum size for a correctly formed ICMP packet.
Pinging a vulnerable network server with
an oversized ICMP packet
will overload the system and cause it to crash.
Think of this like dropping a rock on a small anthill.
Each individual ant can carry a certain amount of
weight while transporting food to and from the anthill.
But if a large rock is dropped on the anthill,
then many ants will be crushed, and the colony is unable to
function until it rebuilds its operations elsewhere.

## SYN Flood Attack

A SYN flood is a type of denial-of-service (DoS) attack that exploits a vulnerability in the TCP/IP handshake. It involves flooding a server with SYN packets, which are the initial connection requests in a TCP connection.

**How it works:**

1. **TCP Three-Way Handshake:**
   - A client sends a SYN packet to a server, requesting a connection.
   - The server responds with a SYN-ACK packet, acknowledging the request and requesting confirmation.
   - The client sends an ACK packet to complete the connection.

2. **SYN Flood Attack:**
   - An attacker sends a large number of SYN packets to a server, spoofing the source IP addresses.
   - The server responds with SYN-ACK packets, but the attacker doesn't send the final ACK packets.
   - The server keeps the connections open, waiting for the final ACKs, which never arrive.
   - This consumes server resources and prevents legitimate connections from being established.

As a result, the server becomes overwhelmed and unable to handle legitimate traffic, effectively denying service to its intended users.

## Intro to Network Security Hardening

### Brute force attacks and OS hardening

In this reading, you’ll learn about brute force attacks. You’ll consider how vulnerabilities can be assessed using virtual machines and sandboxes, and learn ways to prevent brute force attacks using a combination of authentication measures. Implementing various OS hardening tasks can help prevent brute force attacks. An attacker can use a brute force attack to gain access and compromise a network.

Usernames and passwords are among the most common and important security controls in place today. They are used and enforced on everything that stores or accesses sensitive or private information, like personal phones, computers, and restricted applications within an organization. However, a major issue with relying on login credentials as a critical line of defense is that they’re vulnerable to being stolen and guessed by malicious actors.
Brute force attacks

A brute force attack is a trial-and-error process of discovering private information. There are different types of brute force attacks that malicious actors use to guess passwords, including:

Simple brute force attacks. When attackers try to guess a user's login credentials, it’s considered a simple brute force attack. They might do this by entering any combination of usernames and passwords that they can think of until they find the one that works.

Dictionary attacks use a similar technique. In dictionary attacks, attackers use a list of commonly used passwords and stolen credentials from previous breaches to access a system. These are called “dictionary” attacks because attackers originally used a list of words from the dictionary to guess the passwords, before complex password rules became a common security practice.

Using brute force to access a system can be a tedious and time consuming process, especially when it’s done manually. There are a range of tools attackers use to conduct their attacks.
Assessing vulnerabilities

Before a brute force attack or other cybersecurity incident occurs, companies can run a series of tests on their network or web applications to assess vulnerabilities. Analysts can use virtual machines and sandboxes to test suspicious files, check for vulnerabilities before an event occurs, or to simulate a cybersecurity incident.
Virtual machines (VMs)

Virtual machines (VMs) are software versions of physical computers. VMs provide an additional layer of security for an organization because they can be used to run code in an isolated environment, preventing malicious code from affecting the rest of the computer or system. VMs can also be deleted and replaced by a pristine image after testing malware.

VMs are useful when investigating potentially infected machines or running malware in a constrained environment. Using a VM may prevent damage to your system in the event its tools are used improperly. VMs also give you the ability to revert to a previous state. However, there are still some risks involved with VMs. There’s still a small risk that a malicious program can escape virtualization and access the host machine.

You can test and explore applications easily with VMs, and it’s easy to switch between different VMs from your computer. This can also help in streamlining many security tasks.
Sandbox environments

A sandbox is a type of testing environment that allows you to execute software or programs separate from your network. They are commonly used for testing patches, identifying and addressing bugs, or detecting cybersecurity vulnerabilities. Sandboxes can also be used to evaluate suspicious software, evaluate files containing malicious code, and simulate attack scenarios.

Sandboxes can be stand-alone physical computers that are not connected to a network; however, it is often more time- and cost-effective to use software or cloud-based virtual machines as sandbox environments. Note that some malware authors know how to write code to detect if the malware is executed in a VM or sandbox environment. Attackers can program their malware to behave as harmless software when run inside these types of  testing environments.
Prevention measures

Some common measures organizations use to prevent brute force attacks and similar attacks from occurring include:

Salting and hashing: Hashing converts information into a unique value that can then be used to determine its integrity. It is a one-way function, meaning it is impossible to decrypt and obtain the original text. Salting adds random characters to hashed passwords. This increases the length and complexity of hash values, making them more secure.

Multi-factor authentication (MFA) and two-factor authentication (2FA): MFA is a security measure which requires a user to verify their identity in two or more ways to access a system or network. This verification happens using a combination of authentication factors: a username and password, fingerprints, facial recognition, or a one-time password (OTP) sent to a phone number or email. 2FA is similar to MFA, except it uses only two forms of verification.
CAPTCHA and reCAPTCHA: CAPTCHA stands for Completely Automated Public Turing test to tell Computers and Humans Apart. It asks users to complete a simple test that proves they are human. This helps prevent software from trying to brute force a password. reCAPTCHA is a free CAPTCHA service from Google that helps protect websites from bots and malicious software.

Password policies: Organizations use password policies to standardize good password practices throughout the business. Policies can include guidelines on how complex a password should be, how often users need to update passwords, whether passwords can be reused or not, and if there are limits to how many times a user can attempt to log in before their account is suspended.

### Key takeaways

Brute force attacks are a trial-and-er4ror process of guessing passwords. Attacks can be launched manually or through software tools. Methods include simple brute force attacks and dictionary attacks. To protect against brute force attacks, cybersecurity analysts can use sandboxes to test suspicious files, check for vulnerabilities, or to simulate real attacks and virtual machines to conduct vulnerability tests. Some common measures to prevent brute force attacks include: hashing and salting, MFA and/or 2FA, CAPTCHA and reCAPTCHA, and password policies.
