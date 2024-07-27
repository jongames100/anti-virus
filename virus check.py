import os
import vt


def checking_for_virus(file_path,apikey):
    client = vt.Client(apikey)
    global files_amount
    global files_ditected
    global safe_files
    try:
        with open(file_path, "rb") as f:
            print(f'scanning file: {file_path}')
            analysis = client.scan_file(f, wait_for_completion=True)
            files_amount+=1
            
            results = analysis.results
            detected_viruses = [engine for engine, result in results.items() if result["category"] == "malicious"]
            if detected_viruses:
                files_ditected+=1
                for engine in detected_viruses:
                    print(f"in file: {file_path} the vt detected: {engine}: {results[engine]['result']}")
            else:
                print("No viruses detected. The file is clean.")
                safe_files+=1             
    finally:
        client.close()

def folders_files(folder_path,apikey):
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            checking_for_virus(file_path,apikey)

if __name__ == '__main__':
    folder_path = input("Enter the folder path you want to check for viruses:\n")
    apikey=input("pls enter your virus total api key")
    files_amount=0
    files_ditected=0
    safe_files=0
    folders_files(folder_path, apikey)
    print(f'out of the {files_amount} files in the folder {files_ditected} files were found with a virus and {safe_files} file were found safe')