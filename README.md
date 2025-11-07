# 🔍AfriSkana🔍
## 🚨Helping hospitals monitor and identify vulnerable services running on their system's virtual network ports.

AfriSkana is a web-based port scanning tool that prevents threat actors from accessing hospital networks through scanning open virtual ports on a hospital network and providing recommendation on vulnerable services running on the port.
The tool utilises National Vulnerability database to provide information about the vulnerable service on discovered ports with a device.

# 📚Table of contents
1. Overview
2. Features
3. Installation
4. How it works
5. Usage
6. Documentation
   
# ✨Features
💎 User Interface: The tool has web interface where users can interact with the tool easily.<br>
🔍Port Scanning: AfriSkana scan for ports on the specified IP address and returns the port number, status and service as the output.<br>
📌Recommendation: The tools gives Insights from NVD are assoicated with a particular port via the web dashboard.<br>

# 💻Installation
The tool only works on debian based operating system. Therefore it can be used in linux environments.<br>
To install AfriSkana:<br>
1. Clone the AfriSkana repository. <br>
   ```bash
   git clone https://github.com/mbuguaelaine/AfriSkana.git
   ```
3. Install nmap if it's not installed. <br>
   ```bash
   nmap --version # Verfiy if nmap install
   ```
   ```bash
   sudo apt update && sudo apt install nmap
   ```
4. Create a python environment - This helps to install and use the tools libraries without affecting the operating system configurations. <br>
    ```bash
    python -m venv venv_AfriSkana
    ```
5. Activate the virtual environment. <br>
    ```bash
    source venv_Afriskana/bin/activate
    ```
6. Install the tool's dependencies. The dependencies are list in the requirement.txt <br>
    ```bash
    python install -r requirements.txt
    ```
7. Run the app.py to start the tool. <br>
    ```bash
    sudo ./venv_AfriSkana/bin/python app.py
    ```
8. Type the home address on the browser, if you have installed the tool on your local machine i.e 127.0.0.1 <br>

# 🛠 How it works <br>
On the web dashboard, a user inputs the device’s IP address intended for scanning, and chooses between full standard or privacy scan mode. After pressing the scan button, the front-end logic (dashboard.js) sends the inputs to the backend.


The flask server accepts the input and validates the scan mode as it forwards it to the powerhouse (Scanner script). The powerhouse calls Nmap, an open-source port scanning tool, which scans the IP address based on the specified scan mode and returns the port number, service.  The port number and service are passed to the fetch vulnerability function that runs them through the National Vulnerability database, which is a US-based database that stores all the vulnerabilities discovered by researches. The database assigns the Common Vulnerability Exposure Identification number to the service discovered on a port. It also flags if the vulnerability is critical, medium or low under the severity level clause. The output is passed to the recommendation engine, where the vulnerabilities are assigned an alert level based on NVD severity level and finally passed to the web interface to be displayed.

If there’s no vulnerability found on the NVD, the risk mapper dictionary comes to play. The dictionary maps a default recommendation prompting the user to restrict access by placing the port behind the firewall, verify if the service is required, or update/patch the software. Ensuring the tool returns an output and gives an accurate recommendation.

# 📄 Usage
1. Install AfriSkana dependencies as instructed on the installation section.
2. Use the your web browser to access the dashboard, using the 127.0.0.1 address.
3. sign up and set up an account.
4. Finally set the IP address you wish to scan and specify the scan mode.

__This is strictly for networks you have permission to scan__

# 📘 Documentation
For more information about the tool including the problem its solving, research and solution idea. Please visit the AfriSkana Documentation.
