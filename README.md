# CryptoJacker
Why not to borrow some computational power to mine? 

# Disclaimer
<ins>**This project is for educational purpose only! Use it at your own risk!**</ins>

# Description
This malware use a quarter of the victim CPU power to mine Bitcoin.

Since I want the mining process remains hidden to the user, I had to use **x64Hider.exe** and **ProcessHider.exe** executables. 

Since they are detected as virus, I had to encrypt them before (**File0** and **File1** are the encrypted version of them, indeed) 

Once the process is hidden, the malware creates an antivirus path exception where the miner will be placed. 

Finally it creates a task in the Windows planner to schedule its activation at any reboot.
