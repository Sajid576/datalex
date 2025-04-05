from langchain_community.document_loaders import JSONLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma,FAISS
from langchain.schema import Document
from langchain_community.embeddings import OllamaEmbeddings,HuggingFaceEmbeddings

from dotenv import load_dotenv
import os
import shutil
import json
from typing import List, Dict, Any
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("embedding_process.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()


def create_vector_store(chunks: List[Document], persist_directory: str):
    """Create and persist Chroma vector store."""
    # Clear existing vector store if it exists
    if os.path.exists(persist_directory):
        print(f"Clearing existing vector store at {persist_directory}")
        shutil.rmtree(persist_directory)
    
    # Initialize HuggingFace embeddings
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    
    
    # Create and persist Chroma vector store
    print("Creating new vector store...")
    vectordb = FAISS.from_documents(
        documents=chunks,
        embedding=embeddings,
        # persist_directory=persist_directory
    )

    vectordb.save_local(persist_directory)
    print(f"Vector store saved to {persist_directory}")

    return vectordb



def format_log_content(record: dict) -> str:
    """
    Format the log entry into a meaningful text representation.
    """
    content_parts = []

    # Add basic information
    if "src_port" in record:
        content_parts.append(f"Source PORT: {record['src_port']}")
    if "dest_port" in record:
        content_parts.append(f"Destination PORT: {record['dest_port']}")
    if "event_type" in record:
        content_parts.append(f"Event Type: {record['event_type']}")
    if "src_ip" in record:
        content_parts.append(f"Source IP: {record['src_ip']}")
    if "dest_ip" in record:
        content_parts.append(f"Destination IP: {record['dest_ip']}")
    if "proto" in record:
        content_parts.append(f"Protocol: {record['proto']}")

    # Add alert information if present
    if "alert" in record and isinstance(record["alert"], dict):
        alert = record["alert"]
        if "signature" in alert:
            content_parts.append(f"Alert: {alert['signature']}")
        if "category" in alert:
            content_parts.append(f"Category: {alert['category']}")
        if "severity" in alert:
            content_parts.append(f"Severity: {alert['severity']}")

    # Add HTTP information if present
    if "http" in record and isinstance(record["http"], dict):
        http = record["http"]
        if "hostname" in http:
            content_parts.append(f"Host: {http['hostname']}")
        if "url" in http:
            content_parts.append(f"URL: {http['url']}")
        if "http_method" in http:
            content_parts.append(f"Method: {http['http_method']}")
        if "status" in http:
            content_parts.append(f"Status: {http['status']}")

    return " | ".join(content_parts)

def process_suricata_logs(log: dict):
    """
    Process Suricata logs content and prepare documents for embedding.
    """
    try:
        formatted_content = format_log_content(log)
        if formatted_content:
            return formatted_content
        else:
            ""
    except json.JSONDecodeError as e:
        raise Exception(f"Error parsing JSON logs: {str(e)}")
    

def setup_rag_pipeline(data_dir: str):
    processed_texts = []
    
    for filename in os.listdir(data_dir):
        if filename.endswith('.json'):
            file_path = os.path.join(data_dir, filename)
            
            with open(file_path, 'r') as file:
                try:
                    data = json.load(file)
                    
                    # Handle the data whether it's a list or dict
                    if isinstance(data, dict):
                        logs = data.get('logs', [data])
                    else:
                        logs = data
                        
                    print(f"Processing {len(logs)} logs from {filename}...")
                    for log in logs:
                        formatted_text = process_suricata_logs(log)
                        if formatted_text:  # Only add non-empty entries
                            processed_texts.append(formatted_text)
                            
                except json.JSONDecodeError as e:
                    print(f"Error parsing {filename}: {str(e)}")
    
    print(f"Processed {len(processed_texts)} log entries in total")
    
    # Create document splits
    print("Creating document splits...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        length_function=len,
        is_separator_regex=False
    )
    
    # Create Document objects
    documents = [Document(page_content=text, metadata={"source": "suricata_logs"}) for text in processed_texts]
    chunks = text_splitter.split_documents(documents)
    print(f"Created {len(chunks)} chunks")
    
    return chunks

def test_embeddings(vectordb):
    """Test the embedding quality with security-focused queries."""
    test_queries = [
        "high severity alerts",
        "potential port scanning activity",
        "suspicious HTTP traffic",
        "brute force login attempts",
        "malware communication detected"
    ]
    
    print("\n=== Testing Embedding Quality ===")
    for query in test_queries:
        print(f"\nQuery: {query}")
        docs = vectordb.similarity_search(query, k=3)
        
        print("Top 3 results:")
        for i, doc in enumerate(docs):
            print(f"{i+1}. {doc.page_content[:150]}...")

def initiate_vectordb():
    # Define directories
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    db_dir = os.path.join(os.path.dirname(__file__), "vector_db")
    
    # Process Suricata logs
    print("Loading and processing Suricata logs...")
    # chunks = load_and_process_suricata_logs(data_dir)
    # print(f"Created {len(chunks)} chunks from logs")
    chunks = setup_rag_pipeline(data_dir)
    # Create vector store
    print("Creating vector store...")
    vectordb = create_vector_store(chunks, db_dir)

    test_embeddings(vectordb)

    return vectordb
    # print(f"Vector store created and persisted at {db_dir}")

# if __name__ == "__main__":
#     main()
