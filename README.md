# Linux-Process-Monitor
A C-and-Python-based security monitor for Linux using BPF Compiler Collection.

##Prerequisites
You must install the BCC framework and the kernel headers matching your operating system's current kernel version.

**For Debian/Ubuntu/Kali Linux:**
sudo apt update
sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

##Installation & Usage
1. Clone the repository:
  git clone [https://github.com/dmhaider97/Linux-Process-Monitor.git](https://github.com/dmhaider97/Linux-Process-Monitor.git)
  cd Linux-Process-Monitor

2. Run the tool:
  sudo python3 process-monitor.py
