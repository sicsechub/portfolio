import os
import hashlib
import requests

#-----------------------------------------------------------------------------------get_file_size------------------------------------------------------------------------
def get_file_size(file_path):
    try:
        size = os.path.getsize(file_path)
        return size
    except FileNotFoundError:
        return "FileNotFoundError"
    
    
#-----------------------------------------------------------------------------------get_file_type------------------------------------------------------------------------
def get_file_type(file_path):   
    try:
        file_name, file_extension = os.path.splitext(file_path)
        return file_extension.lstrip(".").upper()
    except:
        return "Unknown"


#-----------------------------------------------------------------------------------get_file_md5_hash---------------------------------------------------------------------------
def get_file_md5_hash(file_path):
    
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(65536)  
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()
    except FileNotFoundError:
        return "File not found"
    
    
#-------------------------------------------------------------------------------------analyze_file---------------------------------------------------------------------------------
def analyze_file(file_path):
    
    file_info = {
        "File Size (bytes)": get_file_size(file_path),
        "File Type": get_file_type(file_path),
        "MD5 Hash": get_file_md5_hash(file_path)
        
        
    }
    return file_info


#------------------------------------------------------------------------------------check_id--------------------------------------------------------------------------
def check_id(file_path):
    try:
        
        with open(file_path, "rb") as file:
            files = {"file": (file_path, file)}
        
            
            response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers={"x-apikey": "______api_key_____"})
            response.raise_for_status()  
        
            
            analysis_identifier = response.json()["data"]["id"]
            return analysis_identifier
        
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
    
    
#------------------------------------------------------------------------------------check_malware--------------------------------------------------------------------------
def check_malware(file_path):
    analysis_identifier = check_id(file_path)
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_identifier}"

    headers = {
    "accept": "application/json",
    "x-apikey": "______api key______"
    }

    response = requests.get(url, headers=headers)

    return (response.text)
    

#------------------------------------------------------------------------------------เรียกใช้--------------------------------------------------------------------------

    

    