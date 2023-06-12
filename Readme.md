# pwnagotchi-helper

This repo is an attempt to take the (excellent) work done by [mtagius](https://github.com/mtagius/pwnagotchi-tools) and make everything a little more self contained, and capable of running anywhere there is python.  

The goal is to have as few external dependencies as possible. Currently the only external dependencies needed are `hcxpcaptool` and `hcxpcapngtool` from the [hcxtool](https://github.com/ZerBea/hcxtools) project.  Eventually these may be moved into a Docker container.

Just a simple script you can run once and get the hashcat commands you need.

Only supports python3, tested on python 3.9 and 3.11

## Usage

```
python3 -m venv <path>
python3 -m pip install -r requirements.txt
python3 pwnagotchi-helper.py <ip or hostname of pwnagotchi>
```

Use the --help flag to get a full list of parameters