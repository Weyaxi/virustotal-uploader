# VirusTotal File Uploader

This program allows you to quickly send files to VirusTotal for analysis. By integrating with the VirusTotal API, you can conveniently submit files and receive analysis results directly from your computer.

## Prerequisites

Before using this program, make sure you have the following:

- Python3
- Liblaries from `requirements.txt`
- API key from VirusTotal. (You can obtain an API key by creating an account on the VirusTotal website. See the image below.)

![image](https://github.com/Weyaxi/virustotal-uploader/assets/81961593/32c796fb-61c8-439f-bcf9-c2e2c3e196ab)

## Setup

1. Clone the repository to your local machine or download the source code.

   ```shell
   git clone https://github.com/Weyaxi/virustotal-uploader/
   ```

2. Navigate to the appropriate directory by executing the following command:
   
   ```shell
   cd virustotal-uploader
   ```

4. Install the required dependencies by running the following command:

   ```shell
   pip3 install -r requirements.txt
   ```

5. Open the "main.py" file in a text editor and replace the api_key variable with your own VirusTotal API key.


# Usage

You can use this program with command line using this code:

   ```shell
   python3 main.py -file <path_to_file>
   ```

The program will upload the file to VirusTotal and open the analysis results in your default web browser. (It won't upload the file if it already exists in VirusTotal.)

# Context Menu Integration

To add a "Send to VirusTotal" option to the right-click context menu in Windows Explorer, follow these steps:

1. Open the `with_cmd.reg` or `without_cmd.reg` file (depending on whether you want to open a command prompt while sending the file) in a text editor.

2. Update the script's and python's file path in the registry file to match the location of the necessary files on your system.

3. Save the changes and double-click the registry file to merge the changes into the Windows Registry.

Right-click any file in Windows Explorer and select "Send to VirusTotal". The program will upload the file to VirusTotal and open the analysis results.

![image](https://github.com/Weyaxi/virustotal-uploader/assets/81961593/721366ab-d2c7-49c0-9aa5-e6bc012e374b)

## Demo

### File Already on VirusTotal

![3](https://github.com/Weyaxi/virustotal-uploader/assets/81961593/0c7f8bf2-e0de-4424-8866-09d0c5a5e01c)

### File Currently Not On VirusTotal (You Are Uploading)

![4](https://github.com/Weyaxi/virustotal-uploader/assets/81961593/83296913-bddf-49df-943e-657ea28cb6c6)



