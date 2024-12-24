**NAME:** MANIKALA PREM SAINADH  
**COMPANY:** CODTECH IT SOLUTIONS  
**ID:** CT08DS374  
**DOMAIN:** Cyber Security and Ethical Hacking  
**DURATION:** December 2024 to January 2025  
**MENTOR:** NEHA  


# Overview of the project

# Project: Web Application Penetration Testing

## Objective
The primary goal of this task was to identify and exploit vulnerabilities in a deliberately insecure web application (**DVWA**) to understand how attackers can exploit weaknesses in real-world web applications. This testing also helps us learn how to secure applications by mitigating these vulnerabilities.

---

## Tools Used
1. **DVWA (Damn Vulnerable Web Application):**
   - A vulnerable PHP/MySQL web application used for learning web security.
   - Hosted locally using **XAMPP** on Windows.

2. **SQLmap:**
   - An automated SQL injection tool that helps identify and exploit SQL vulnerabilities.

3. **OWASP ZAP (Optional):**
   - A GUI-based web vulnerability scanner (if used).

---

## Setup Process

### 1. Installing DVWA
- Downloaded DVWA from its [GitHub repository](https://github.com/digininja/DVWA).
- Configured it to run locally on Windows using **XAMPP**.
- Set up the MySQL database connection by editing the `config.inc.php` file with valid credentials.

### 2. Running DVWA
- Accessed DVWA via `http://localhost/dvwa/` after starting Apache and MySQL in XAMPP.
- Logged into DVWA using default credentials (`admin/password`).

### 3. Adjusting DVWA Security Levels
- Set DVWA’s **Security Level** to **Low** for ease of exploitation during testing.

---

## Testing Process

### 1. SQL Injection

#### What is SQL Injection?
SQL Injection is a code injection technique that exploits vulnerabilities in an application's database queries by injecting malicious SQL statements.

#### How We Tested:
1. Navigated to the **SQL Injection** module in DVWA.
2. Entered the following payload in the **User ID** field:
   ```sql
   1' OR '1'='1
   ```
   - **Result:** The application returned all user records, proving it was vulnerable to SQL injection.
3. Used SQLmap for automation:
   - **Command:**
     ```bash
     sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/" --data="id=1&Submit=Submit" --batch
     ```
   - **Result:** SQLmap identified the vulnerability and was able to dump the database, exposing user credentials.

#### Significance:
Demonstrates how attackers can extract sensitive information like usernames and passwords from a poorly secured database.

---

### 2. Cross-Site Scripting (XSS)

#### What is XSS?
XSS is an attack where malicious scripts are injected into trusted websites. It allows attackers to steal cookies, hijack sessions, or deface web pages.

#### How We Tested:
1. Navigated to the **XSS (Stored)** module in DVWA.
2. Injected the following payload in a text field:
   ```html
   <script>alert('XSS Test');</script>
   ```
3. **Result:**
   - The script was stored and executed when the page reloaded, showing a pop-up with "XSS Test."
   - Proved the application was vulnerable to Stored XSS.

#### Significance:
Highlighted the danger of storing unvalidated user input, which can lead to attacks affecting all users who view the page.

---

### 3. Mitigation Recommendations
After identifying these vulnerabilities, the following measures were suggested to secure the application:

#### For SQL Injection:
- Use **Parameterized Queries** (Prepared Statements) to separate SQL logic from user input.
- Validate and sanitize all user inputs before processing.
- Implement a Web Application Firewall (WAF).

#### For XSS:
- Use proper input validation and output encoding to sanitize user input.
- Implement a Content Security Policy (CSP) to restrict script execution.
- Escape special characters in HTML.

---

## Challenges Encountered

### 1. MySQL Authentication Issue:
- The error `Access denied for user 'user'@'localhost'` occurred due to insufficient privileges for the MySQL user `user`.
- **Resolution:** Logged in as `root` and granted proper permissions to `user`.

### 2. Configuration Adjustments:
- Required editing the `config.inc.php` file to set correct database credentials.

---

## Outcome
1. Successfully identified and exploited SQL Injection and XSS vulnerabilities in DVWA.
   - Below is an example of SQL Injection output, showcasing extracted user data from the database.

2. Automated SQL injection exploitation using SQLmap.
   - Below is an example of SQLmap output showing database dumping results.

3. Gained hands-on experience with common web vulnerabilities and their mitigations.
   - Below is an example of XSS exploitation with the alert pop-up.

---

## Learning Highlights

### 1. Importance of Secure Coding:
- Demonstrated how simple coding mistakes, like improper input handling, can lead to severe vulnerabilities.

### 2. Proactive Testing:
- Emphasized the need for regular security testing and vulnerability assessments.

### 3. Mitigation Techniques:
- Practical insights into securing web applications using industry-standard techniques.
