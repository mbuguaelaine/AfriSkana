# AfriSkana
Helping hospitals monitor and identify vulnerable services running on their systems virtual oports.

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
💎 User Interface: The tool has web interface where users can interact with the tool easily.
🔍Port Scanning: AfriSkana scan for ports on the specified ip address and returns the port number, status and service as the output.
📌Recommendation: The tools gives Insights from NVD are assoicated with a particular port via the web dashboard.

# 💻Installation
The tool only works on debian based operating system. Therefore it can be used in linux environments.
To install AfriSkana:
1. Clone the AfriSkana repository
   <git clone https://github.com/mbuguaelaine/AfriSkana.git>
2. Install nmap if it's not installed
    <nmap --version # Verfiy if nmap install> 
    <sudo apt update && sudo apt install nmap>
3. Create a python environment - This helps to install and use the tools libraries without affecting the operating system configurations
    <python -m venv venv_AfriSkana>
4. Activate the virtual environment
    <source venv_Afriskana/bin/activate>
5. Install the tool's dependencies. The dependencies are list in the requirement.txt
    <python install -r requirements.txt>
6. Run the app.py to start the tool
    <sudo ./venv_AfriSkana/bin/python app.py>
7. Type the home address on the browser, if you have installed the tool on your local machine i.e 127.0.0.1

# 🛠 How it works
