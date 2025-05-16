from smolagents import OpenAIServerModel, CodeAgent, ToolCallingAgent, HfApiModel, tool, GradioUI

from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import OllamaEmbeddings, HuggingFaceEmbeddings
# from ingest_logs import initiate_vectordb
import ollama
import gradio as gr
import pandas as pd
import time
import psutil
import numpy as np
import threading
from datetime import datetime
import queue
import requests
from src.utils.env import get_env

reasoning_model_id = getenv("REASONING_MODEL_ID")
default_tool_model_id = getenv("TOOL_MODEL_ID")
virustotal_api_key = getenv("VIRUSTOTAL_API_KEY")

available_models = ["qwen2.5:7b-instruct-q4_K_M", "llama3:8b"]

# Default system prompt
default_system_prompt = """ 
You are a security log analyst. Based on the following Suricata log entries and our conversation history,
please answer the question professionally and provide specific details from the logs when relevant.
"""

# Performance metrics storage
performance_metrics = {
    "inference_times": [],
    "retrieval_times": [],
    "memory_usage": [],
    "throughput": [],
    "token_generation_rates": [],
    "timestamps": [],
    "model_used": []  # Track which model was used for each query
}

# Lock for thread-safe metrics updates
metrics_lock = threading.Lock()

def get_model(model_id):
    return OpenAIServerModel(
            model_id=model_id,
            api_base="http://localhost:11434/v1",
            api_key="ollama"
        )

# Create the reasoner for better RAG
reasoning_model = get_model(reasoning_model_id)
reasoner = CodeAgent(tools=[], model=reasoning_model, add_base_tools=False, max_steps=2)

# Function to estimate tokens in a string
def estimate_tokens(text):
    # Rough estimation: ~4 characters per token
    return len(text) // 4

# VirusTotal API functions
def query_virustotal(indicator, indicator_type):
    """
    Query VirusTotal API for information about a specific indicator
    
    Args:
        indicator (str): The indicator to query (URL, hash, domain, IP)
        indicator_type (str): The type of indicator ('url', 'file', 'domain', 'ip')
        
    Returns:
        dict: VirusTotal response or error message
    """
    if not virustotal_api_key:
        return {"error": "VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to your .env file."}
    
    base_url = "https://www.virustotal.com/api/v3/"
    
    headers = {
        "x-apikey": virustotal_api_key,
        "Content-Type": "application/json"
    }
    
    try:
        if indicator_type == "url":
            # URL needs to be encoded properly
            import urllib.parse
            url_id = urllib.parse.quote(indicator, safe='')
            response = requests.get(f"{base_url}urls/{url_id}", headers=headers)
        elif indicator_type == "file":
            # File hash analysis
            response = requests.get(f"{base_url}files/{indicator}", headers=headers)
        elif indicator_type == "domain":
            response = requests.get(f"{base_url}domains/{indicator}", headers=headers)
        elif indicator_type == "ip":
            response = requests.get(f"{base_url}ip_addresses/{indicator}", headers=headers)
        else:
            return {"error": f"Unsupported indicator type: {indicator_type}"}
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"VirusTotal API error: {response.status_code}",
                "details": response.text
            }
            
    except Exception as e:
        return {"error": f"Error querying VirusTotal: {str(e)}"}

def format_virustotal_results(vt_results):
    """
    Format VirusTotal results into a readable summary
    
    Args:
        vt_results (dict): VirusTotal API response
        
    Returns:
        str: Formatted summary
    """
    if "error" in vt_results:
        return f"Error: {vt_results['error']}"
    
    try:
        # Extract attributes from the results
        attributes = vt_results.get("data", {}).get("attributes", {})
        
        # Different indicator types have different attributes
        if "last_analysis_stats" in attributes:
            stats = attributes["last_analysis_stats"]
            
            # Basic summary
            summary = f"""
## VirusTotal Analysis Summary

- **Detection Ratio**: {stats.get('malicious', 0)}/{sum(stats.values())}
- **Malicious Verdicts**: {stats.get('malicious', 0)}
- **Suspicious Verdicts**: {stats.get('suspicious', 0)}
- **Clean Verdicts**: {stats.get('harmless', 0)}
- **Analysis Date**: {datetime.fromtimestamp(attributes.get('last_analysis_date', 0)).strftime('%Y-%m-%d %H:%M:%S')}
"""
            
            # Add more details based on indicator type
            if "categories" in attributes:
                categories = attributes["categories"]
                if categories:
                    summary += "\n### Categories\n"
                    for source, category in categories.items():
                        summary += f"- **{source}**: {category}\n"
            
            if "tags" in attributes:
                tags = attributes["tags"]
                if tags:
                    summary += "\n### Tags\n"
                    summary += ", ".join(tags)
                    summary += "\n"
            
            # Add top 5 security vendors that flagged it as malicious
            if "last_analysis_results" in attributes:
                results = attributes["last_analysis_results"]
                malicious_vendors = [
                    (vendor, result["result"]) 
                    for vendor, result in results.items() 
                    if result.get("category") == "malicious"
                ]
                
                if malicious_vendors:
                    summary += "\n### Top Security Vendor Detections\n"
                    for vendor, result in malicious_vendors[:5]:
                        summary += f"- **{vendor}**: {result}\n"
            
            return summary
        else:
            return "Unable to find analysis results in the VirusTotal response."
            
    except Exception as e:
        return f"Error parsing VirusTotal results: {str(e)}"

def detect_indicator_type(query):
    """
    Detect the type of security indicator in a query string
    
    Args:
        query (str): The query text
        
    Returns:
        tuple: (indicator, indicator_type) or (None, None) if no indicator detected
    """
    import re
    
    # MD5, SHA-1, SHA-256 hash detection
    hash_patterns = [
        (r'\b[a-fA-F0-9]{32}\b', 'file'),  # MD5
        (r'\b[a-fA-F0-9]{40}\b', 'file'),  # SHA-1
        (r'\b[a-fA-F0-9]{64}\b', 'file'),  # SHA-256
    ]
    
    for pattern, indicator_type in hash_patterns:
        match = re.search(pattern, query)
        if match:
            return match.group(0), indicator_type
    
    # IP address detection
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, query)
    if match:
        return match.group(0), 'ip'
    
    # URL detection
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    match = re.search(url_pattern, query)
    if match:
        return match.group(0), 'url'
    
    # Domain detection (simplified pattern)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    match = re.search(domain_pattern, query)
    if match:
        # Filter out common words that might match the domain pattern
        potential_domain = match.group(0).lower()
        common_words = ["example.com", "domain.com"]
        if not any(word in potential_domain for word in common_words):
            return potential_domain, 'domain'
    
    return None, None

def ollama_streaming_llm(question, context, chat_history, model_id, system_prompt, stream_queue):
    """
    Streaming version of the LLM function that puts chunks into a queue for gradio streaming
    """
    history_text = ""
    if chat_history:
        history_text = "Previous conversation:\n"
        for q, a in chat_history:
            history_text += f"Human: {q}\nAssistant: {a}\n"

    # Check if there's a security indicator to query in VirusTotal
    indicator, indicator_type = detect_indicator_type(question)
    vt_context = ""
    
    if indicator and indicator_type:
        # Get VirusTotal information
        vt_results = query_virustotal(indicator, indicator_type)
        vt_context = format_virustotal_results(vt_results)
    
    formatted_prompt = f"""
    {system_prompt}

    {history_text}

    Question: {question}

    Log Entries:
    {context}
    
    {f"VirusTotal Analysis for {indicator} ({indicator_type}):" if indicator else ""}
    {vt_context if vt_context else ""}

    Analysis:"""

    try:
        start_time = time.time()
        mem_before = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB
        
        # Use streaming response from Ollama
        full_response = ""
        for chunk in ollama.chat(
            model=model_id,
            messages=[{'role': 'user', 'content': formatted_prompt}],
            stream=True  # Enable streaming
        ):
            if 'message' in chunk and 'content' in chunk['message']:
                content_chunk = chunk['message']['content']
                full_response += content_chunk
                # Put chunk in queue for streaming in UI
                stream_queue.put(content_chunk)
        
        # Signal end of streaming
        stream_queue.put(None)
        
        end_time = time.time()
        mem_after = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB
        
        elapsed_time = end_time - start_time
        output_tokens = estimate_tokens(full_response)
        token_rate = output_tokens / elapsed_time if elapsed_time > 0 else 0
        
        # Update performance metrics
        with metrics_lock:
            performance_metrics["inference_times"].append(elapsed_time)
            performance_metrics["memory_usage"].append(mem_after - mem_before)
            performance_metrics["token_generation_rates"].append(token_rate)
            performance_metrics["timestamps"].append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            performance_metrics["model_used"].append(model_id)
            
        return full_response
    except Exception as e:
        error_msg = f"Error querying Ollama with model {model_id}: {str(e)}"
        stream_queue.put(error_msg)
        stream_queue.put(None)  # Signal end of streaming
        return error_msg


def create_rag_chain(vectorstore):
   
    retriever = vectorstore.as_retriever(
        search_type="similarity",
        search_kwargs={"k": 5}
    )

    def rag_chain(question, history, model_id, system_prompt, stream_queue):
        try:
            # Measure retrieval time
            retrieval_start = time.time()
            retrieved_docs = retriever.invoke(question)
            retrieval_time = time.time() - retrieval_start
            
            # Update retrieval metrics
            with metrics_lock:
                performance_metrics["retrieval_times"].append(retrieval_time)
            
            start_time = time.time()
            formatted_context = "\n\n".join(doc.page_content for doc in retrieved_docs)
            
            # Use streaming version of the LLM function
            response = ollama_streaming_llm(question, formatted_context, history, model_id, system_prompt, stream_queue)
            
            # Measure throughput (questions per minute)
            end_time = time.time()
            total_time = end_time - start_time
            throughput = 60 / total_time if total_time > 0 else 0  # queries per minute
            
            # Update throughput metrics
            with metrics_lock:
                performance_metrics["throughput"].append(throughput)
                
            return response
        except Exception as e:
            error_msg = f"Error in RAG chain: {str(e)}"
            stream_queue.put(error_msg)
            stream_queue.put(None)  # Signal end of streaming
            return error_msg

    return rag_chain

def get_performance_stats():
    """Generate a report of current performance metrics"""
    with metrics_lock:
        if not performance_metrics["inference_times"]:
            return "No performance data available yet."
        
        # Convert data to DataFrame for easier analysis
        df = pd.DataFrame({
            "model": performance_metrics["model_used"],
            "inference_time": performance_metrics["inference_times"],
            "retrieval_time": performance_metrics["retrieval_times"] if performance_metrics["retrieval_times"] else [0] * len(performance_metrics["inference_times"]),
            "memory_usage": performance_metrics["memory_usage"],
            "throughput": performance_metrics["throughput"] if performance_metrics["throughput"] else [0] * len(performance_metrics["inference_times"]),
            "token_rate": performance_metrics["token_generation_rates"]
        })
        
        # Overall stats
        avg_inference = np.mean(performance_metrics["inference_times"])
        avg_retrieval = np.mean(performance_metrics["retrieval_times"]) if performance_metrics["retrieval_times"] else 0
        avg_memory = np.mean(performance_metrics["memory_usage"])
        avg_throughput = np.mean(performance_metrics["throughput"]) if performance_metrics["throughput"] else 0
        avg_token_rate = np.mean(performance_metrics["token_generation_rates"])
        
        # Get the last timestamp
        last_timestamp = performance_metrics["timestamps"][-1] if performance_metrics["timestamps"] else "N/A"
        
        # Model-specific stats
        model_stats = ""
        for model in set(performance_metrics["model_used"]):
            model_df = df[df["model"] == model]
            model_stats += f"""
### {model}
- Queries: {len(model_df)}
- Avg Inference Time: {model_df["inference_time"].mean():.2f} seconds
- Avg Token Rate: {model_df["token_rate"].mean():.2f} tokens/second
- Avg Memory Usage: {model_df["memory_usage"].mean():.2f} MB
"""
        
        return f"""
## Performance Metrics (Last Updated: {last_timestamp})

### Overall Stats
- **Average Inference Time**: {avg_inference:.2f} seconds
- **Average Retrieval Latency**: {avg_retrieval:.2f} seconds
- **Average Memory Usage**: {avg_memory:.2f} MB
- **Average Throughput**: {avg_throughput:.2f} queries/minute
- **Average Token Generation Rate**: {avg_token_rate:.2f} tokens/second

### Per-Model Stats
{model_stats}

*Based on {len(performance_metrics["inference_times"])} total queries*
"""

def export_performance_metrics():
    """Export performance metrics to Excel"""
    with metrics_lock:
        if not performance_metrics["inference_times"]:
            return None
            
        # Create DataFrame
        df = pd.DataFrame({
            "Timestamp": performance_metrics["timestamps"],
            "Model": performance_metrics["model_used"],
            "Inference Time (s)": performance_metrics["inference_times"],
            "Retrieval Time (s)": performance_metrics["retrieval_times"] if performance_metrics["retrieval_times"] else [0] * len(performance_metrics["timestamps"]),
            "Memory Usage (MB)": performance_metrics["memory_usage"],
            "Throughput (queries/min)": performance_metrics["throughput"] if performance_metrics["throughput"] else [0] * len(performance_metrics["timestamps"]),
            "Token Rate (tokens/s)": performance_metrics["token_generation_rates"]
        })
        
        # Export to Excel
        filename = f"performance_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        df.to_excel(filename, index=False)
        return filename


def create_gradio_interface():
    """
    Create and launch the Gradio interface with chat functionality.
    """
    try:
        print("Setting up RAG pipeline...")
        vectordb = initiate_vectordb()
        
        rag_chain_fn = create_rag_chain(vectordb)

        conversation_log = [] 
        
        # Generator function for streaming
        def stream_response(message, chat_history, model_choice, system_prompt):
            # Initialize a queue for streaming chunks
            stream_queue = queue.Queue()
            
            # Start RAG chain in a separate thread
            def process_query():
                rag_chain_fn(message, chat_history, model_choice, system_prompt, stream_queue)
                
            threading.Thread(target=process_query).start()
            
            # Start with an empty response
            bot_message = ""
            
            # Stream the response chunks
            while True:
                chunk = stream_queue.get()
                if chunk is None:  # End of streaming signal
                    break
                bot_message += chunk
                yield "", chat_history + [[message, bot_message]]
            
            # Record this conversation after it's complete
            conversation_log.append({
                "Question": message, 
                "Response": bot_message,
                "Model": model_choice,
                "System Prompt": system_prompt,
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Final yield with the complete response
            return "", chat_history + [[message, bot_message]]

        # Function to export conversation logs
        def export_conversation_logs():
            if not conversation_log:
                return None
                
            # Convert to DataFrame and export
            df = pd.DataFrame(conversation_log)
            excel_file = f"conversation_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            df.to_excel(excel_file, index=False)
            return excel_file

        # Function to directly query VirusTotal
        def direct_vt_query(indicator, indicator_type):
            if not indicator:
                return "Please enter an indicator to query."
                
            if not indicator_type:
                # Try to auto-detect
                detected_indicator, detected_type = detect_indicator_type(indicator)
                if detected_type:
                    indicator = detected_indicator
                    indicator_type = detected_type
                else:
                    return "Could not automatically detect indicator type. Please select a type."
            
            vt_results = query_virustotal(indicator, indicator_type)
            return format_virustotal_results(vt_results)

        # Updated CSS with glass effect
        css = """
        body, .gradio-container {
            background: linear-gradient(135deg, #000000, #1a1a1a, #2d2d2d) !important;
            color: white !important;
        }
        .tabs {
            background-color: rgba(30, 30, 30, 0.5) !important;
            backdrop-filter: blur(10px) !important;
            -webkit-backdrop-filter: blur(10px) !important;
            border-radius: 10px !important;
            padding: 10px !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3) !important;
        }
        .chatbot {
            background-color: rgba(20, 20, 20, 0.5) !important;
            backdrop-filter: blur(10px) !important;
            -webkit-backdrop-filter: blur(10px) !important;
            border-radius: 10px !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3) !important;
        }
        .message.user {
            background-color: rgba(42, 42, 42, 0.7) !important;
            color: white !important;
            border-radius: 8px !important;
        }
        .message.bot {
            background-color: rgba(30, 30, 30, 0.7) !important;
            color: white !important;
            border-left: 3px solid rgba(150, 150, 150, 0.3) !important;
            border-radius: 8px !important;
        }
        .examples-panel {
            background-color: rgba(30, 30, 30, 0.5) !important;
            backdrop-filter: blur(8px) !important;
            -webkit-backdrop-filter: blur(8px) !important;
            border-radius: 8px !important;
            padding: 5px !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
        }
        .examples {
            background-color: rgba(30, 30, 30, 0.5) !important;
            backdrop-filter: blur(8px) !important;
            -webkit-backdrop-filter: blur(8px) !important;
            border-radius: 8px !important;
            padding: 5px !important;
        }
        button.primary {
            background-color: rgba(68, 68, 68, 0.8) !important;
            backdrop-filter: blur(5px) !important;
            -webkit-backdrop-filter: blur(5px) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            transition: all 0.3s ease !important;
        }
        button.primary:hover {
            background-color: rgba(85, 85, 85, 0.9) !important;
            transform: translateY(-2px) !important;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3) !important;
        }
        input, textarea {
            background-color: rgba(42, 42, 42, 0.7) !important;
            color: rgba(255, 255, 255, 0.9) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            backdrop-filter: blur(5px) !important;
            -webkit-backdrop-filter: blur(5px) !important;
        }
        input::placeholder, textarea::placeholder {
            color: rgba(200, 200, 200, 0.7) !important;
        }
        input:focus, textarea:focus {
            border-color: rgba(150, 150, 150, 0.5) !important;
            background-color: rgba(50, 50, 50, 0.7) !important;
            box-shadow: 0 0 0 1px rgba(150, 150, 150, 0.2) !important;
        }
        h1, h2, h3, h4 {
            color: #f0f0f0 !important;
            text-shadow: 0px 2px 4px rgba(0, 0, 0, 0.3) !important;
        }
        .performance-metrics {
            background-color: rgba(20, 20, 20, 0.5) !important;
            backdrop-filter: blur(10px) !important;
            -webkit-backdrop-filter: blur(10px) !important;
            padding: 15px !important;
            border-radius: 10px !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3) !important;
        }
        /* Fix for Send button interaction */
        #component-0 [data-testid="textbox"] {
            color: white !important;
            transition: background-color 0.3s ease !important;
        }
        /* Ensure chat history remains visible during loading */
        .wrap.generating {
            opacity: 0.8 !important;
        }
        /* Additional glass effects for dropdown */
        select, .gr-dropdown {
            background-color: rgba(42, 42, 42, 0.7) !important;
            backdrop-filter: blur(8px) !important;
            -webkit-backdrop-filter: blur(8px) !important;
            color: white !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
        }
        /* Make scrollbars match the theme */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(30, 30, 30, 0.4);
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(100, 100, 100, 0.6);
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(120, 120, 120, 0.8);
        }
        /* Streaming text effect */
        @keyframes blink {
            0% { opacity: 1; }
            50% { opacity: 0; }
            100% { opacity: 1; }
        }
        .streaming-cursor {
            display: inline-block;
            width: 0.5em;
            height: 1em;
            background-color: rgba(255, 255, 255, 0.7);
            animation: blink 1s infinite;
            vertical-align: middle;
            margin-left: 2px;
        }
        """

        # Create a custom theme (compatible with older Gradio versions)
        custom_theme = gr.themes.Soft()
        
        # Create a state variable to store system prompt across tabs
        system_prompt_state = gr.State(default_system_prompt)
        
        with gr.Blocks(theme=custom_theme, css=css) as iface:
            gr.Markdown("# 🔒 Datalex")
            gr.Markdown("Ask questions about your Suricata logs. The system will analyze relevant log entries and provide detailed answers.")

            with gr.Tab("Chat"):
                # Model selection dropdown
                model_dropdown = gr.Dropdown(
                    choices=available_models,
                    label="Select LLM Model",
                    value=available_models[0],  # Default to first model
                    info="Choose which model to use for analysis"
                )
                
                chatbot = gr.Chatbot(
                    [],
                    elem_id="chatbot",
                    bubble_full_width=False,
                    avatar_images=(None, "🔒"),
                    height=500
                )

                with gr.Row():
                    txt = gr.Textbox(
                        show_label=False,
                        placeholder="Ask a question about the Suricata logs...",
                        container=False
                    )
                    submit_btn = gr.Button("Send", variant="primary")

                with gr.Row():
                    clear_btn = gr.Button("Clear History")
                    export_btn = gr.Button("Export Conversation to Excel")

                # Example questions
                gr.Examples(
                    [
                        "Show me any SQL injection attempts",
                        "What are the most common protocols in the logs?",
                        "Are there any suspicious HTTP requests?",
                        "List all high severity alerts",
                        "What are the top source IPs making connections?",
                        "Check this IP: 8.8.8.8 for any threat intelligence",
                        "Is domain example.com known to be malicious?",
                        "Analyze this hash: 44d88612fea8a8f36de82e1278abb02f"
                    ],
                    txt,
                    label="Example Questions"
                )
            
            # Add the new AI Configuration tab
            with gr.Tab("AI Configuration"):
                gr.Markdown("## Customize AI Behavior")
                gr.Markdown("Configure how the AI assistant analyzes and responds to your queries by editing the system prompt.")
                
                current_system_prompt = gr.Textbox(
                    label="System Prompt",
                    value=default_system_prompt,
                    lines=8,
                    placeholder="Enter instructions for the AI assistant...",
                    info="This prompt guides how the AI interprets and responds to your questions."
                )
                
                with gr.Row():
                    save_prompt_btn = gr.Button("Save Configuration", variant="primary")
                    reset_prompt_btn = gr.Button("Reset to Default")
                
                config_status = gr.Markdown("Current configuration is active")
                
                # Function to update system prompt state
                def update_system_prompt(new_prompt):
                    return new_prompt, "✅ Configuration saved successfully!"
                
                # Function to reset system prompt
                def reset_system_prompt():
                    return default_system_prompt, "✅ Reset to default configuration"
                
                # Set up event handlers for system prompt
                save_prompt_btn.click(
                    update_system_prompt, 
                    inputs=[current_system_prompt], 
                    outputs=[system_prompt_state, config_status]
                )
                
                reset_prompt_btn.click(
                    reset_system_prompt,
                    outputs=[current_system_prompt, config_status]
                )
                
                gr.Markdown("""
                ### Example Configurations
                
                #### Security Expert
                ```
                You are an expert security analyst with deep knowledge of network security and threat detection.
                Analyze the provided Suricata logs thoroughly and provide professional insights with technical details.
                Be precise in identifying potential threats, attack vectors, and recommended mitigations.
                ```
                
                #### Executive Summary Focus
                ```
                You are presenting to C-level executives. Based on the Suricata logs, provide concise, 
                high-level summaries of security issues with business impact. Avoid technical jargon unless
                necessary and focus on risk levels, potential business impacts, and key recommendations.
                ```
                
                #### Beginner-Friendly Mode
                ```
                You are a patient security instructor helping someone learn about security logs.
                Explain the Suricata log entries in simple terms, define technical concepts,
                and provide educational context about different types of security events.
                ```
                """)
                
           
            # Add new VirusTotal Lookup tab
            with gr.Tab("VirusTotal Lookup"):
                gr.Markdown("## VirusTotal Threat Intelligence")
                gr.Markdown("Search for security indicators to get threat intelligence from VirusTotal.")
                
                with gr.Row():
                    vt_indicator = gr.Textbox(
                        label="Enter Indicator",
                        placeholder="URL, IP address, domain, or file hash",
                        info="Enter a security indicator to check against VirusTotal"
                    )
                    
                    vt_indicator_type = gr.Dropdown(
                        choices=["auto", "url", "ip", "domain", "file"],
                        label="Indicator Type",
                        value="auto",
                        info="Select the type of indicator or use 'auto' for automatic detection"
                    )
                
                vt_search_btn = gr.Button("Search VirusTotal", variant="primary")
                vt_results = gr.Markdown("Results will appear here")
                
                # Set up VirusTotal search function
                def vt_search_handler(indicator, indicator_type):
                    if indicator_type == "auto":
                        detected_indicator, detected_type = detect_indicator_type(indicator)
                        if detected_type:
                            return direct_vt_query(detected_indicator, detected_type)
                        else:
                            return "Could not automatically detect indicator type. Please select a specific type."
                    else:
                        return direct_vt_query(indicator, indicator_type)
                
                vt_search_btn.click(vt_search_handler, [vt_indicator, vt_indicator_type], vt_results)
                
            with gr.Tab("Performance Metrics"):
                metrics_md = gr.Markdown(get_performance_stats())  # Initial metrics display
                refresh_btn = gr.Button("Refresh Metrics")
                export_metrics_btn = gr.Button("Export Metrics to Excel")
                
                # Set up refresh function
                refresh_btn.click(get_performance_stats, outputs=metrics_md)
                export_metrics_btn.click(export_performance_metrics)
            
            # Handler for clearing chat history
            def clear_history():
                return [], []  # Return empty chatbot and empty chat_history
                
            # Set up event handlers for streaming
            submit_btn.click(stream_response, [txt, chatbot, model_dropdown], [txt, chatbot])
            txt.submit(stream_response, [txt, chatbot, model_dropdown], [txt, chatbot])
            clear_btn.click(clear_history, None, [chatbot])
            export_btn.click(export_conversation_logs)
            
            # Add description
            gr.Markdown("""
            **Note**:
            - Select a model from the dropdown to process your queries
            - Each model has different capabilities and performance characteristics
            - The chat history is used as context for follow-up questions
            - Use 'Clear History' to start a fresh conversation
            - The system maintains conversation context to provide more relevant answers
            - Performance metrics are collected in real-time for each model
            - Compare model performance in the Performance Metrics tab
            - Conversation logs can be exported to Excel for further analysis
            - Responses are now streamed in real-time for a more interactive experience
            - Use the VirusTotal Lookup tab to get threat intelligence on security indicators
            - Supports searching URLs, IPs, domains, and file hashes
            - Automatic indicator type detection is available
            """)

        return iface

    except Exception as e:
        print(f"Error creating Gradio interface: {str(e)}")

# Example prompt: Compare and contrast the services offered by RankBoost and Omni Marketing
def main():
    # GradioUI(primary_agent).launch(share=True)
    iface = create_gradio_interface()
    iface.launch(share=True)
if __name__ == "__main__":
    main()