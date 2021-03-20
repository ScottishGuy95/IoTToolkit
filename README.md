# IoT Toolkit
An effective and user-friendly vulnerability detection and mitigation toolkit that can be used to test the security of IoT devices on a home network.
The program has been tested successfully on the following systems:
* Ubuntu 20.04
* Windows 10

Makes use of the MIRAI Botnet wordlists when testing credentials.

Developed as part of my university honours project

# Requirements
* Download & install Python V3.8 or above [LINK](https://www.python.org/downloads/)

### Windows
Using CMD, install the following:
```
pip3 install virtualenv
```

Download the IoTToolkit-main file manually using the green button above or if git is installed:
```
git clone https://github.com/ScottishGuy95/IoTToolkit.git
```

Inside the IoTToolkit folder, using CMD, type:
```
python -m virtualenv venv
```

Enter the new virtual environment, type:
```
venv\Scripts\activate
```


Install project requirements:
```
pip3 install -r requirements.txt
```

### Linux
Ensure your system is up to date:
```
sudo apt update
```

Check the correct package lists are available:
```
sudo apt install software-properties-common
```

As Linux can accommodate multiple versions of python, the following is required:
```
sudo add-apt-repository ppa:deadsnakes/ppa
```

Install Python (If you have not already):
```
sudo apt install python3.9
```

Download python3-pip:
```
sudo apt-get install python3-pip
```

Download virtualenv to create our virtual environments to keep python projects separate:
```
sudo pip3 install virtualenv
```

Install the git package:
```
sudo apt install git
```

net-tools is required to accommodate Linux systems:
```
sudo apt-get install net-tools
```

Go into the directory you wish to install the IoT Toolkit and type:
```
git clone https://github.com/ScottishGuy95/IoTToolkit.git
```

Enter the IoT Toolkit directory and create a virtual environment:
```
virtualenv -p python3 venv
```

Activate your new environment using:
```
source venv/bin/activate
```

Finally, install the project requirements using:
```
pip3 install -r requirements.txt
```

# Usage
Using either terminal (Linux) or CMD (Windows), ensure you are inside of your virtual environment
and inside of the IoT Toolkit folder, then type:
```
python3 toolkit.py
```
Once the program runs, you will be asked to enter your network information (best to enter `no`).
If you fully understand network notation and understand your entire network range, enter `yes`.
Otherwise, type `no` and the program will detect this for you manually.

Upon completion. A scan log can be found inside the folder where you downloaded the IoT Toolkit.
Files are named in the following format: `scan_data_time.txt`

Mitigation methods for any security issues or vulnerabilities can be found in the CMD/terminal output window.

# License
[MIT](https://choosealicense.com/licenses/mit/)