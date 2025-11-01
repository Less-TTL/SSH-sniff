# SSH-sniff

This XRO tool is used for mass-scanning SSH servers. It uses a Python-based IP generator to test every IP for SSH connections and also reports whether an IP appears to be a honeypot.
[SV1.zip](https://github.com/user-attachments/files/23283655/SV1.zip)
[main.py](https://github.com/user-attachments/files/23283656/main.py)

---

## How to use

1. Download the file into your Linux `Downloads` folder.  
   If you are running Windows with WSL, leave the files in your Windows `Downloads` folder and access them from WSL (see example below).

2. Install Python (example for Debian/Ubuntu):
```bash
sudo apt update
sudo apt install python3 -y
```
Press Enter when prompted.

3. Change into the project directory:
```bash
cd "/mnt/c/Users/YourPcUsername/Path/to/where/it's/set/like/Downloads/or/Documents/main/"
```
(If you're on Linux, `cd` into the folder where you downloaded and extracted the repository.)

Example photo:  
<img width="460" height="61" alt="image" src="https://github.com/user-attachments/assets/37acd83d-af19-4ee2-ad2b-a15db7d441f9" />

---

## Running

Once you are in the project folder, run:
```bash
python3 main.py
```

Example screenshot:  
<img width="439" height="25" alt="image" src="https://github.com/user-attachments/assets/0413b51d-950b-4323-b17b-039483c2aa98" />

The GUI of the script should open. Example:  
<img width="614" height="360" alt="image" src="https://github.com/user-attachments/assets/1fb29c90-1726-4fd9-b5b4-ac73c80df684" />

---

## Enable Public IPs

1. From the menu, press option **3** to enable Public IPs.  
   <img width="392" height="334" alt="image" src="https://github.com/user-attachments/assets/c3503a68-9ad3-4596-9597-a9e01536de50" />

2. Press **T** to enable. The program should confirm and return you to the main menu.

---

## Scanning SSH connections

1. From the main menu, press **1** to start scanning SSH connections. You will see a screen like this:  
   <img width="519" height="176" alt="image" src="https://github.com/user-attachments/assets/90f361e6-086f-44dd-bde3-c2ad83a08466" />

2. Enter the number of IPs to scan in each **batch**. For example, `1000`.  
   - I normally set it to `1000`. Keep in mind larger batch sizes (like `1000`) will be much slower.  
   - You can edit `main.py` to change the maximum limit, but increasing the limit may make the scan significantly slower.

3. After entering the batch size, the script will ask for an output file name. You can accept the default by pressing **Enter**.  
   <img width="453" height="87" alt="image" src="https://github.com/user-attachments/assets/80aebed7-557b-42ad-88ac-7d646e30c42c" />

4. You'll see live output of the IPs being scanned:  
   <img width="646" height="803" alt="image" src="https://github.com/user-attachments/assets/239bdd23-9c64-42e0-97d5-52a1cd6fe9a9" />

5. To stop scanning, press `CTRL+C`. Press it again if necessary; the script will exit and save your scan results.  
   <img width="607" height="387" alt="image" src="https://github.com/user-attachments/assets/f5269d1b-085c-462f-ae62-fbc1d6468298" />

---

## Inspecting scan results (SSH IP OSINT)

If you want more details about the IPs you collected:

1. Re-open the script and choose option **2** for **SSH IP OSINT**. This will gather information about the IPs.  
   <img width="611" height="161" alt="image" src="https://github.com/user-attachments/assets/be493043-c04e-4e00-aba7-1a9bef8f4c43" />

2. Press **1** to select an output file to analyze.  
   <img width="553" height="304" alt="image" src="https://github.com/user-attachments/assets/d677acbd-a8c1-4b26-8d0f-3ada01d60ba7" />

3. When prompted, press **Y** to get more information on each IP (recommended).

You will see output similar to this while OSINT runs:  
<img width="964" height="272" alt="image" src="https://github.com/user-attachments/assets/c1419766-aac1-4946-8307-60a82392cdd4" />

Wait until it finishes:  
<img width="513" height="395" alt="image" src="https://github.com/user-attachments/assets/84c5a00a-2909-4abe-830b-08729d222f76" />

---

## Notes

- Scanning large numbers of IPs can consume significant bandwidth and CPU and may be slow depending on your hardware and network.  
- Modify `main.py` carefully if you change batch sizes or timeouts — higher concurrency can drastically affect performance.  
- Use this tool responsibly and only scan networks/IPs you own or have explicit permission to test.

---

THAT'S ALL TO IT :3

<img width="513" height="395" alt="image" src="https://github.com/user-attachments/assets/84c5a00a-2909-4abe-830b-08729d222f76" />
