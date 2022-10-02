
# sha256-hashcheck

Script gets sha256 hash for user inputed file, then does a virus check with VirusTotal.



## Install

To run this script, you will need to install the following dependency using the pip package manager.

`pip install requests`


## VirusTotal API

#### You will need to obtain a free API key from VirusTotal
If you do not have a VirusTotal account sign up here: https://www.virustotal.com/gui/join-us

After signing up, or if you already have an account, obtain your API key here: https://www.virustotal.com/gui/my-apikey

After obtaining your key, go to the script and place it as the vt_key variable.
```python
vt_key = 'your_key_here'
```



## Usage
*This script will currently only work for macOS and Linux.*

When you run the script you will be prompted for a file path.
```
Enter file path:
```

After entering a file path the script will ouput your sha256 hash and complete a virus scan from VirusTotal.

```
Your SHA256 file hash is xxxxxxxxxxxxxxxxxxxx
----------------------------------------------
Scan performed by VirusTotal:
Total number of different vendors scanning is xx, of those different scans x were positive.
For more details go to https://www.virustotal.com/gui/file/xxxxxxxxxxxxxxxxxxxxx
```
## License

[MIT](https://choosealicense.com/licenses/mit/)

