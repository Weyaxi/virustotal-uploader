import requests
import webbrowser
import os
import hashlib
import argparse

def main(file_path):
    api_key = "<your_api_key>"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }


    def sha256_file():
        with open(file_path, 'rb') as file:
            sha256_hash = hashlib.sha256(file.read()).hexdigest()
            file.close()
        return sha256_hash


    def is_size_greater_than_250mb():
        return True if (os.path.getsize(file_path) / 1048576) > 250 else False


    def check_if_file_exists():
        global response

        url = "https://www.virustotal.com/api/v3/files/upload_url"

        response = requests.get(url, headers=headers)
        return response


    sha = sha256_file()
    check_link = f"https://www.virustotal.com/api/v3/files/{sha}"
    try:
        requests.get(check_link, headers=headers).json()['error']['code']
    except KeyError:  # File already exists
        webbrowser.open(f"https://www.virustotal.com/gui/file/{sha}")
        exit()


    url = check_if_file_exists().json()['data'] if is_size_greater_than_250mb() else "https://www.virustotal.com/api/v3/files"

    files = {"file": (str(file_path).split("/")[-1], open(file_path, "rb"), "text/plain")}

    response = requests.post(url, files=files, headers=headers)

    url = response.json()['data']['links']['self']
    response_for_analyses = requests.get(url, headers=headers)

    file_info = response_for_analyses.json()['meta']['file_info']
    link_hash = file_info['sha256'] if 'sha256' in file_info else file_info['md5']

    link = f"https://www.virustotal.com/gui/file/{link_hash}"
    webbrowser.open(link)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Submit a file to VirusTotal for analysis")
    parser.add_argument("-file", dest="file_path", help="Path to the file for analysis")

    args = parser.parse_args()

    if args.file_path:
        main(args.file_path)
    else:
        print("Please provide the path to the file using the -file argument.")
