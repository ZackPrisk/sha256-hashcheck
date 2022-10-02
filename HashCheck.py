import subprocess
import sys
from os.path import exists
import requests
import platform


# Script only supports macOS and Linux

# Function to get SHA256 hash for given file path, if invalid file input the program will stop
def main():
    file = input("Enter file path: ")
    os = platform.system()
    while exists(file):
        if 'Darwin' in os:
            return subprocess.Popen('shasum -a 256 ' + file,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=True).stdout.read().decode()[:65]
        elif 'Linux' in os:
            return subprocess.Popen('sha256sum ' + file,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=True).stdout.read().decode()[:65]
    else:
        sys.exit(print('Invalid file path'))


# Variable for main function
hashed_file = main()

# Enter API Key obtained from VirusTotal
vt_key = ''

# URL Variable for API request
url = 'https://www.virustotal.com/vtapi/v2/file/report'

# Parameters to pass (API Key and File Hash)
params = {'apikey': vt_key, 'resource': hashed_file}

# GET VirusTotal Data from API
response = requests.get(url, params=params)

# Extract JSON from response
x = response.json()

# Parce JSON from response
total_scans = x["total"]
positive_scans = x["positives"]
permalink = x["permalink"]

if __name__ == '__main__':
    print(f'Your SHA256 file hash is {hashed_file}''\n----------------------------------------------')
    print("Scan performed by VirusTotal:")
    print(f"Total number of different vendors scanning is {total_scans}, of those different scans {positive_scans} were positive.\nFor more details go to {permalink}")
