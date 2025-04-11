# Faraday Architecture

Faraday is a comprehensive security platform that combines a Flask-based API with background task processing capabilities. The system is designed to handle both synchronous HTTP requests and real-time WebSocket communications, while efficiently processing long-running tasks through a distributed worker system.

## System Overview

```ascii
+------------------+
|                  |
|     Clients      |
|  - Api Clients   |
|  - Cloud Agents  |
|  - Faraday Agents|
|  - Faraday-cli   |
|  - Faraday's     |
|    React UI      |
|                  |
+------------------+
        |
        v
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|  Faraday Flask   |     |  Message Broker  |     |  Faraday Workers |
|       API        |<--->| (Redis/RabbitMQ) |<--->|     (Celery)     |
|    (HTTP/WS)     |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
        |                                                |
        |                                                |
        v                                                v
+------------------+                               +------------------+
|                  |                               |                  |
|    PostgreSQL    |                               |  Long Tasks:     |
|    Database      |                               |  - Exec Reports  |
|                  |                               |  - Scan Imports  |
|                  |                               |  - Stats Gen     |
+------------------+                               +------------------+
```

## Components

- **Faraday Flask API**: Main application server handling HTTP and WebSocket requests
- **Message Broker**: Queue system (Redis/RabbitMQ) for task distribution
- **Faraday Workers**: Celery workers processing background tasks
- **PostgreSQL**: Primary database for data storage
- **Long Tasks**: Background jobs processed by workers
- **Clients**: Various client interfaces including:
  - Api Clients: External applications using Faraday's API
  - Cloud Agents: Cloud-based agents for distributed task execution
  - [Faraday Agents](https://github.com/infobyte/faraday_agent_dispatcher): Local agents for task execution
  - [Faraday-cli](https://github.com/infobyte/faraday-cli): Command-line interface
  - Faraday's React UI: Web-based user interface 