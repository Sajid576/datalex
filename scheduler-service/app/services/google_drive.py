import os
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from settings import GOOGLE_DRIVE_CREDENTIALS_PATH,TEMP_PATH,SURICATA_LOG_CHUNK_SIZE

class ChunkFileService:
    last_read_index = 0
    
    def clone_json_file_to_list(self, source_path, destination_path):
        try:
            json_objects = []
            
            with open(source_path, "r", encoding="utf-8") as src_file:
                for line in src_file:
                    json_objects.append(json.loads(line.strip()))

            with open(destination_path, "w", encoding="utf-8") as dest_file:
                json.dump(json_objects, dest_file, indent=4)

            print(f"Successfully cloned and transformed JSON into a list: {destination_path}")
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON format! {e}")
        except Exception as e:
            print(f"Error cloning JSON file: {e}")


    def upload_json_chunk(self, file_path):
        chunk_size = int(SURICATA_LOG_CHUNK_SIZE)
        print("LAST READ INDEX:",ChunkFileService.last_read_index)
        sample_suricata_json_path =TEMP_PATH+'/sample/suricata.json'
        self.clone_json_file_to_list(file_path,sample_suricata_json_path)
        # Read the JSON file
        with open(sample_suricata_json_path, 'r') as file:
            data = json.load(file)

        end_index = ChunkFileService.last_read_index + chunk_size

        current_chunk = data[self.last_read_index:end_index]

        ChunkFileService.last_read_index = end_index

        output_file_path = os.path.join(TEMP_PATH, f'chunk_{ChunkFileService.last_read_index - chunk_size}_to_{ChunkFileService.last_read_index - 1}_suricata.json')

        with open(output_file_path, 'w') as output_file:
            json.dump(current_chunk, output_file, indent=4)

        print(f"Stored {len(current_chunk)} records in {output_file_path}")

        return output_file_path

class GoogleDriveService:
    def __init__(self):
        with open(GOOGLE_DRIVE_CREDENTIALS_PATH, "r") as file:
            credentials_data = json.load(file)
    
        self.credentials = service_account.Credentials.from_service_account_info(
            credentials_data,
            scopes=["https://www.googleapis.com/auth/drive.file"]
        )
        self.service = build('drive', 'v3', credentials=self.credentials)

    def upload_file(self, file_path: str, drive_link: str = None) -> str:
        print('=================LOG TRANSFER PROCESSING===========')
        
        chunkFileService = ChunkFileService()
        output_file_path = chunkFileService.upload_json_chunk(file_path)
        # GithubService().backup_file(output_file_path)
        # file_metadata = {'name': file_path.split('/')[-1]}
        file_metadata = {'name': output_file_path.split('/')[-1]}
        
        if drive_link:
            folder_id = drive_link.split('/')[-1].split('?')[0] 
            file_metadata['parents'] = [folder_id]

        media = MediaFileUpload(output_file_path, resumable=True)
        file = self.service.files().create(body=file_metadata, media_body=media, fields='id').execute()

        self.service.permissions().create(
            fileId=file.get('id'),
            body={'type': 'anyone', 'role': 'reader'}
        ).execute()

        shareable_link = f"https://drive.google.com/file/d/{file.get('id')}/view?usp=sharing"

        print('=================LOG TRANSFER SUCCESS===========')
        return shareable_link
