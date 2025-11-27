# Wireless Intrusion Detection System API

**WIPS** is a feature-rich desktop application framework that leverages React, Tauri, and Rust to deliver powerful Wi-Fi management and security tools. Designed for developers, it simplifies building cross-platform, secure desktop apps with a modern user interface. The core features include:
- 🧩**Modular Architecture:** Organized codebase with clear separation of frontend, backend, and system integrations.
- 🔒**Wi-Fi Security & Monitoring:** Scan networks, detect evil twins, assess risks, and manage blacklists and whitelists.
- 🎨**Rich UI Components:** Customizable tables, modals, navigation, and risk indicators for intuitive data visualization.
- ⚙️**System Integration:** Seamless control over Wi-Fi connections, network info retrieval, and system commands.
- 🚀**Scalable Development:** State management with Redux, API layer, and TypeScript configurations for maintainability.
  
Main Repository is [wisp](https://github.com/IgorMilya/wips.git)

### Installation
To install WIPS API server, follow these steps:

1. **Clone the repository**  
   ```bash
   git clone https://github.com/IgorMilya/wisp-server.git
   ```
2. **Navigate to the project directory for UI**  
   ```bash
   cd wips-server
   ```
3. **Install all dependencies from Cargo.toml **  
   ```bash
   cargo build
   ```
4. **Set local enviroment**
   This application uses env MONGO_DB_URL for security reasons. Before running, you need to create in the root directory .env file and specify the MONGO_DB_URL environment variable. This MONGO_DB_URL is your MongoDB API that will communicate with MongoDB. How it looks like: mongodb+srv://<username>:<db_password>@<project_name_in_mongoDB>.j5ndz0i.mongodb.net/?retryWrites=true&w=majority&appName=<project_name_in_mongoDB>. You can get this value by creating your own DB in MongoDB. 
   
### Usage
To start the WIPS API Server, run the following command:
   ```bash
   cargo run
   ```
This will start a local http://localhost:3000 server for communication with MongoDB and your UI Application.


## Routes
- **/blacklist** get all blacklist collection
- **/blacklist/{id}** get particular blacklisted network
- **/whitelist** get all whitelist collection
- **/whitelist{id}** get particular whitelisted network
