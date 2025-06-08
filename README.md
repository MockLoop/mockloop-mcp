![MockLoop](logo.png "MockLoop")

# MockLoop MCP - AI-Native Testing Platform

[![PyPI version](https://img.shields.io/pypi/v/mockloop-mcp.svg)](https://pypi.org/project/mockloop-mcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/mockloop-mcp.svg)](https://pypi.org/project/mockloop-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/mockloop-mcp.svg)](https://pypi.org/project/mockloop-mcp/)
[![License](https://img.shields.io/pypi/l/mockloop-mcp.svg)](https://github.com/mockloop/mockloop-mcp/blob/main/LICENSE)
[![Tests](https://github.com/mockloop/mockloop-mcp/workflows/Tests/badge.svg)](https://github.com/mockloop/mockloop-mcp/actions)
[![Documentation](https://img.shields.io/badge/docs-available-brightgreen.svg)](https://docs.mockloop.com)
[![AI-Native](https://img.shields.io/badge/AI--Native-Testing-blue.svg)](https://docs.mockloop.com/ai-integration/overview/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

**The world's first AI-native API testing platform** powered by the Model Context Protocol (MCP). MockLoop MCP revolutionizes API testing with comprehensive AI-driven scenario generation, automated test execution, and intelligent analysis capabilities.

**🚀 Revolutionary Capabilities:** 5 AI Prompts • 15 Scenario Resources • 16 Testing Tools • 10 Context Tools • 4 Core Tools • Complete MCP Integration

**📚 Documentation:** https://docs.mockloop.com  
**📦 PyPI Package:** https://pypi.org/project/mockloop-mcp/  
**🐙 GitHub Repository:** https://github.com/mockloop/mockloop-mcp

## 🌟 What Makes MockLoop MCP Revolutionary?

MockLoop MCP represents a paradigm shift in API testing, introducing the world's first **AI-native testing architecture** that combines:

- **🤖 AI-Driven Test Generation**: 5 specialized MCP prompts for intelligent scenario creation  
- **📦 Community Scenario Packs**: 15 curated testing resources with community architecture  
- **⚡ Automated Test Execution**: 30 comprehensive MCP tools for complete testing workflows (16 testing + 10 context + 4 core)  
- **🔄 Stateful Testing**: Advanced context management with GlobalContext and AgentContext  
- **📊 Enterprise Compliance**: Complete audit logging and regulatory compliance tracking  
- **🏗️ Dual-Port Architecture**: Eliminates /admin path conflicts with separate mocked API and admin ports

## 🎯 Core AI-Native Architecture

### MCP Audit Logging
**Enterprise-grade compliance and regulatory tracking**  
- Complete request/response audit trails  
- Regulatory compliance monitoring  
- Performance metrics and analytics  
- Security event logging  

### MCP Prompts (5 AI-Driven Capabilities)  
**Intelligent scenario generation powered by AI**  
- [`analyze_openapi_for_testing`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_prompts.py#L301) - Comprehensive API analysis for testing strategies
- [`generate_scenario_config`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_prompts.py#L426) - Dynamic test scenario configuration
- [`optimize_scenario_for_load`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_prompts.py#L521) - Load testing optimization
- [`generate_error_scenarios`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_prompts.py#L633) - Error condition simulation
- [`generate_security_test_scenarios`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_prompts.py#L732) - Security vulnerability testing

### MCP Resources (15 Scenario Packs)  
**Community-driven testing scenarios with advanced architecture**  
- **Load Testing Scenarios**: High-volume traffic simulation  
- **Error Simulation Packs**: Comprehensive error condition testing  
- **Security Testing Suites**: Vulnerability assessment scenarios   
- **Performance Benchmarks**: Standardized performance testing  
- **Integration Test Packs**: Cross-service testing scenarios  
- **Community Architecture**: Collaborative scenario sharing and validation  

### MCP Tools (16 Automated Testing Tools)  
**Complete automated test execution capabilities**  

#### Scenario Management (4 tools)  
- [`validate_scenario_config`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L174) - Scenario validation and verification
- [`deploy_scenario`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L267) - Automated scenario deployment
- [`switch_scenario`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L385) - Dynamic scenario switching
- [`list_active_scenarios`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L476) - Active scenario monitoring

#### Test Execution (4 tools)  
- [`execute_test_plan`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L577) - Comprehensive test plan execution
- [`run_test_iteration`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L816) - Individual test iteration management
- [`run_load_test`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L945) - Load testing execution
- [`run_security_test`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2019) - Security testing automation

#### Analysis & Reporting (4 tools)
- [`analyze_test_results`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2142) - Intelligent test result analysis
- [`generate_test_report`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2225) - Comprehensive reporting
- [`compare_test_runs`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2310) - Test run comparison and trends
- [`get_performance_metrics`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2418) - Performance metrics collection

#### Workflow Management (4 tools)
- [`create_test_session`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2524) - Test session initialization
- [`end_test_session`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2579) - Session cleanup and finalization
- [`schedule_test_suite`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2646) - Automated test scheduling
- [`monitor_test_progress`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_tools.py#L2702) - Real-time progress monitoring

### MCP Context Management (10 Stateful Workflow Tools)
**Advanced state management for complex testing workflows**

#### Context Creation & Management
- [`create_test_session_context`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1431) - Test session state management
- [`create_workflow_context`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1447) - Complex workflow orchestration
- [`create_agent_context`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1463) - AI agent state management

#### Data Management
- [`get_context_data`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1477) - Context data retrieval
- [`update_context_data`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1486) - Dynamic context updates
- [`list_contexts_by_type`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1508) - Context discovery and listing

#### Snapshot & Recovery
- [`create_context_snapshot`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1494) - State snapshot creation
- [`restore_context_snapshot`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1502) - State rollback capabilities

#### Global Context
- [`get_global_context_data`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1516) - Cross-session data sharing
- [`update_global_context_data`](https://github.com/MockLoop/mockloop-mcp/blob/main/src/mockloop_mcp/mcp_context.py#L1523) - Global state management

## 🚀 Quick Start

Get started with the world's most advanced AI-native testing platform:

```bash
# 1. Install MockLoop MCP
pip install mockloop-mcp

# 2. Verify installation
mockloop-mcp --version

# 3. Configure with your MCP client (Cline, Claude Desktop, etc.)
# See configuration examples below
```

## 📋 Prerequisites

- Python 3.10+
- Pip package manager
- Docker and Docker Compose (for containerized mock servers)
- An MCP-compatible client (Cline, Claude Desktop, etc.)

## 🔧 Installation

### Option 1: Install from PyPI (Recommended)

```bash
# Install the latest stable version
pip install mockloop-mcp

# Or install with optional dependencies
pip install mockloop-mcp[dev]   # Development tools
pip install mockloop-mcp[docs]  # Documentation tools
pip install mockloop-mcp[all]   # All optional dependencies

# Verify installation
mockloop-mcp --version
```

### Option 2: Development Installation

```bash
# Clone the repository
git clone https://github.com/mockloop/mockloop-mcp.git
cd mockloop-mcp

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

## ⚙️ Configuration

### MCP Client Configuration

#### Cline (VS Code Extension)

Add to your Cline MCP settings file:

```json
{
  "mcpServers": {
    "MockLoopLocal": {
      "autoApprove": [],
      "disabled": false,
      "timeout": 60,
      "command": "mockloop-mcp",
      "args": [],
      "transportType": "stdio"
    }
  }
}
```

#### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "mockloop": {
      "command": "mockloop-mcp",
      "args": []
    }
  }
}
```

#### Virtual Environment Installations

For virtual environment installations, use the full Python path:

```json
{
  "mcpServers": {
    "MockLoopLocal": {
      "command": "/path/to/your/venv/bin/python",
      "args": ["-m", "mockloop_mcp"],
      "transportType": "stdio"
    }
  }
}
```

## 🛠️ Available MCP Tools

### Core Mock Generation

#### `generate_mock_api`
Generate sophisticated FastAPI mock servers with dual-port architecture.

**Parameters:**
- `spec_url_or_path` (string, required): API specification URL or local file path
- `output_dir_name` (string, optional): Output directory name
- `auth_enabled` (boolean, optional): Enable authentication middleware (default: true)
- `webhooks_enabled` (boolean, optional): Enable webhook support (default: true)
- `admin_ui_enabled` (boolean, optional): Enable admin UI (default: true)
- `storage_enabled` (boolean, optional): Enable storage functionality (default: true)

**Revolutionary Dual-Port Architecture:**
- **Mocked API Port**: Serves your API endpoints (default: 8000)
- **Admin UI Port**: Separate admin interface (default: 8001)
- **Conflict Resolution**: Eliminates /admin path conflicts in OpenAPI specs
- **Enhanced Security**: Port-based access control and isolation

### Advanced Analytics

#### `query_mock_logs`
Query and analyze request logs with AI-powered insights.

**Parameters:**
- `server_url` (string, required): Mock server URL
- `limit` (integer, optional): Maximum logs to return (default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)
- `method` (string, optional): Filter by HTTP method
- `path_pattern` (string, optional): Regex pattern for path filtering
- `time_from` (string, optional): Start time filter (ISO format)
- `time_to` (string, optional): End time filter (ISO format)
- `include_admin` (boolean, optional): Include admin requests (default: false)
- `analyze` (boolean, optional): Perform AI analysis (default: true)

**AI-Powered Analysis:**
- Performance metrics (P95/P99 response times)
- Error rate analysis and categorization
- Traffic pattern detection
- Automated debugging recommendations
- Session correlation and tracking

#### `discover_mock_servers`
Intelligent server discovery with dual-port architecture support.

**Parameters:**
- `ports` (array, optional): Ports to scan (default: common ports)
- `check_health` (boolean, optional): Perform health checks (default: true)
- `include_generated` (boolean, optional): Include generated mocks (default: true)

**Advanced Discovery:**
- Automatic architecture detection (single-port vs dual-port)
- Health status monitoring
- Server correlation and matching
- Port usage analysis

#### `manage_mock_data`
Dynamic response management without server restart.

**Parameters:**
- `server_url` (string, required): Mock server URL
- `operation` (string, required): Operation type ("update_response", "create_scenario", "switch_scenario", "list_scenarios")
- `endpoint_path` (string, optional): API endpoint path
- `response_data` (object, optional): New response data
- `scenario_name` (string, optional): Scenario name
- `scenario_config` (object, optional): Scenario configuration

**Dynamic Capabilities:**
- Real-time response updates
- Scenario-based testing
- Runtime configuration management
- Zero-downtime modifications

## 🌐 MCP Proxy Functionality

MockLoop MCP includes revolutionary proxy capabilities that enable seamless switching between mock and live API environments. This powerful feature transforms your testing workflow by providing:

### Core Proxy Capabilities

- **🔄 Seamless Mode Switching**: Transition between mock, proxy, and hybrid modes without code changes
- **🎯 Intelligent Routing**: Smart request routing based on configurable rules and conditions
- **🔐 Universal Authentication**: Support for API Key, Bearer Token, Basic Auth, and OAuth2
- **📊 Response Comparison**: Automated comparison between mock and live API responses
- **⚡ Zero-Downtime Switching**: Change modes dynamically without service interruption

### Operational Modes

#### Mock Mode (`MOCK`)
- All requests handled by generated mock responses
- Predictable, consistent testing environment
- Ideal for early development and isolated testing
- No external dependencies or network calls

#### Proxy Mode (`PROXY`)
- All requests forwarded to live API endpoints
- Real-time data and authentic responses
- Full integration testing capabilities
- Network-dependent operation with live credentials

#### Hybrid Mode (`HYBRID`)
- Intelligent routing between mock and proxy based on rules
- Conditional switching based on request patterns, headers, or parameters
- Gradual migration from mock to live environments
- A/B testing and selective endpoint proxying

### Quick Start Example

```python
from mockloop_mcp.mcp_tools import create_mcp_plugin

# Create a proxy-enabled plugin
plugin_result = await create_mcp_plugin(
    spec_url_or_path="https://api.example.com/openapi.json",
    mode="hybrid",  # Start with hybrid mode
    plugin_name="example_api",
    target_url="https://api.example.com",
    auth_config={
        "auth_type": "bearer_token",
        "credentials": {"token": "your-token"}
    },
    routing_rules=[
        {
            "pattern": "/api/critical/*",
            "mode": "proxy",  # Critical endpoints use live API
            "priority": 10
        },
        {
            "pattern": "/api/dev/*",
            "mode": "mock",   # Development endpoints use mocks
            "priority": 5
        }
    ]
)
```

### Advanced Features

- **🔍 Response Validation**: Compare mock vs live responses for consistency
- **📈 Performance Monitoring**: Track response times and throughput across modes
- **🛡️ Error Handling**: Graceful fallback mechanisms and retry policies
- **🎛️ Dynamic Configuration**: Runtime mode switching and rule updates
- **📋 Audit Logging**: Complete request/response tracking across all modes

### Authentication Support

The proxy system supports comprehensive authentication schemes:

- **API Key**: Header, query parameter, or cookie-based authentication
- **Bearer Token**: OAuth2 and JWT token support
- **Basic Auth**: Username/password combinations
- **OAuth2**: Full OAuth2 flow with token refresh
- **Custom**: Extensible authentication handlers for proprietary schemes

### Use Cases

- **Development Workflow**: Start with mocks, gradually introduce live APIs
- **Integration Testing**: Validate against real services while maintaining test isolation
- **Performance Testing**: Compare mock vs live API performance characteristics
- **Staging Validation**: Ensure mock responses match production API behavior
- **Hybrid Deployments**: Route critical operations to live APIs, others to mocks

**📚 Complete Guide**: For detailed configuration, examples, and best practices, see the [MCP Proxy Guide](docs/guides/mcp-proxy-guide.md).
## 🤖 AI Framework Integration

MockLoop MCP provides native integration with popular AI frameworks:

### LangGraph Integration

```python
from langgraph.graph import StateGraph, END
from mockloop_mcp import MockLoopClient

# Initialize MockLoop client
mockloop = MockLoopClient()

def setup_ai_testing(state):
    """AI-driven test setup"""
    # Generate mock API with AI analysis
    result = mockloop.generate_mock_api(
        spec_url_or_path="https://api.example.com/openapi.json",
        output_dir_name="ai_test_environment"
    )
    
    # Use AI prompts for scenario generation
    scenarios = mockloop.analyze_openapi_for_testing(
        api_spec=state["api_spec"],
        analysis_depth="comprehensive",
        include_security_tests=True
    )
    
    state["mock_server_url"] = "http://localhost:8000"
    state["test_scenarios"] = scenarios
    return state

def execute_ai_tests(state):
    """Execute AI-generated test scenarios"""
    # Deploy AI-generated scenarios
    for scenario in state["test_scenarios"]:
        mockloop.deploy_scenario(
            server_url=state["mock_server_url"],
            scenario_config=scenario
        )
        
        # Execute load tests with AI optimization
        results = mockloop.run_load_test(
            server_url=state["mock_server_url"],
            scenario_name=scenario["name"],
            duration=300,
            concurrent_users=100
        )
        
        # AI-powered result analysis
        analysis = mockloop.analyze_test_results(
            test_results=results,
            include_recommendations=True
        )
        
        state["test_results"].append(analysis)
    
    return state

# Build AI-native testing workflow
workflow = StateGraph(dict)
workflow.add_node("setup_ai_testing", setup_ai_testing)
workflow.add_node("execute_ai_tests", execute_ai_tests)
workflow.set_entry_point("setup_ai_testing")
workflow.add_edge("setup_ai_testing", "execute_ai_tests")
workflow.add_edge("execute_ai_tests", END)

app = workflow.compile()
```

### CrewAI Multi-Agent Testing

```python
from crewai import Agent, Task, Crew
from mockloop_mcp import MockLoopClient

# Initialize MockLoop client
mockloop = MockLoopClient()

# AI Testing Specialist Agent
api_testing_agent = Agent(
    role='AI API Testing Specialist',
    goal='Generate and execute comprehensive AI-driven API tests',
    backstory='Expert in AI-native testing with MockLoop MCP integration',
    tools=[
        mockloop.generate_mock_api,
        mockloop.analyze_openapi_for_testing,
        mockloop.generate_scenario_config
    ]
)

# Performance Analysis Agent
performance_agent = Agent(
    role='AI Performance Analyst',
    goal='Analyze API performance with AI-powered insights',
    backstory='Specialist in AI-driven performance analysis and optimization',
    tools=[
        mockloop.run_load_test,
        mockloop.get_performance_metrics,
        mockloop.analyze_test_results
    ]
)

# Security Testing Agent
security_agent = Agent(
    role='AI Security Testing Expert',
    goal='Conduct AI-driven security testing and vulnerability assessment',
    backstory='Expert in AI-powered security testing methodologies',
    tools=[
        mockloop.generate_security_test_scenarios,
        mockloop.run_security_test,
        mockloop.compare_test_runs
    ]
)

# Define AI-driven tasks
ai_setup_task = Task(
    description='Generate AI-native mock API with comprehensive testing scenarios',
    agent=api_testing_agent,
    expected_output='Mock server with AI-generated test scenarios deployed'
)

performance_task = Task(
    description='Execute AI-optimized performance testing and analysis',
    agent=performance_agent,
    expected_output='Comprehensive performance analysis with AI recommendations'
)

security_task = Task(
    description='Conduct AI-driven security testing and vulnerability assessment',
    agent=security_agent,
    expected_output='Security test results with AI-powered threat analysis'
)

# Create AI testing crew
ai_testing_crew = Crew(
    agents=[api_testing_agent, performance_agent, security_agent],
    tasks=[ai_setup_task, performance_task, security_task],
    verbose=True
)

# Execute AI-native testing workflow
results = ai_testing_crew.kickoff()
```

### LangChain AI Testing Tools

```python
from langchain.agents import Tool, AgentExecutor, create_react_agent
from langchain.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from mockloop_mcp import MockLoopClient

# Initialize MockLoop client
mockloop = MockLoopClient()

# AI-Native Testing Tools
def ai_generate_mock_api(spec_path: str) -> str:
    """Generate AI-enhanced mock API with intelligent scenarios"""
    # Generate mock API
    result = mockloop.generate_mock_api(spec_url_or_path=spec_path)
    
    # Use AI to analyze and enhance
    analysis = mockloop.analyze_openapi_for_testing(
        api_spec=spec_path,
        analysis_depth="comprehensive",
        include_security_tests=True
    )
    
    return f"AI-enhanced mock API generated: {result}\nAI Analysis: {analysis['summary']}"

def ai_execute_testing_workflow(server_url: str) -> str:
    """Execute comprehensive AI-driven testing workflow"""
    # Create test session context
    session = mockloop.create_test_session_context(
        session_name="ai_testing_session",
        configuration={"ai_enhanced": True}
    )
    
    # Generate and deploy AI scenarios
    scenarios = mockloop.generate_scenario_config(
        api_spec=server_url,
        scenario_types=["load", "error", "security"],
        ai_optimization=True
    )
    
    results = []
    for scenario in scenarios:
        # Deploy scenario
        mockloop.deploy_scenario(
            server_url=server_url,
            scenario_config=scenario
        )
        
        # Execute tests with AI monitoring
        test_result = mockloop.execute_test_plan(
            server_url=server_url,
            test_plan=scenario["test_plan"],
            ai_monitoring=True
        )
        
        results.append(test_result)
    
    # AI-powered analysis
    analysis = mockloop.analyze_test_results(
        test_results=results,
        include_recommendations=True,
        ai_insights=True
    )
    
    return f"AI testing workflow completed: {analysis['summary']}"

# Create LangChain tools
ai_testing_tools = [
    Tool(
        name="AIGenerateMockAPI",
        func=ai_generate_mock_api,
        description="Generate AI-enhanced mock API with intelligent testing scenarios"
    ),
    Tool(
        name="AIExecuteTestingWorkflow",
        func=ai_execute_testing_workflow,
        description="Execute comprehensive AI-driven testing workflow with intelligent analysis"
    )
]

# Create AI testing agent
llm = ChatOpenAI(temperature=0)
ai_testing_prompt = PromptTemplate.from_template("""
You are an AI-native testing assistant powered by MockLoop MCP.
You have access to revolutionary AI-driven testing capabilities including:
- AI-powered scenario generation
- Intelligent test execution
- Advanced performance analysis
- Security vulnerability assessment
- Stateful workflow management

Tools available: {tools}
Tool names: {tool_names}

Question: {input}
{agent_scratchpad}
""")

agent = create_react_agent(llm, ai_testing_tools, ai_testing_prompt)
agent_executor = AgentExecutor(agent=agent, tools=ai_testing_tools, verbose=True)

# Execute AI-native testing
response = agent_executor.invoke({
    "input": "Generate a comprehensive AI-driven testing environment for a REST API and execute full testing workflow"
})
```

## 🏗️ Dual-Port Architecture

MockLoop MCP introduces a revolutionary **dual-port architecture** that eliminates common conflicts and enhances security:

### Architecture Benefits

- **🔒 Enhanced Security**: Complete separation of mocked API and admin functionality
- **⚡ Zero Conflicts**: Eliminates /admin path conflicts in OpenAPI specifications
- **📊 Clean Analytics**: Admin calls don't appear in mocked API metrics
- **🔄 Independent Scaling**: Scale mocked API and admin services separately
- **🛡️ Port-Based Access Control**: Enhanced security through network isolation

### Port Configuration

```python
# Generate mock with dual-port architecture
result = mockloop.generate_mock_api(
    spec_url_or_path="https://api.example.com/openapi.json",
    business_port=8000,  # Mocked API port
    admin_port=8001,     # Admin UI port
    admin_ui_enabled=True
)
```

### Access Points

- **Mocked API**: `http://localhost:8000` - Your API endpoints
- **Admin UI**: `http://localhost:8001` - Management interface
- **API Documentation**: `http://localhost:8000/docs` - Interactive Swagger UI
- **Health Check**: `http://localhost:8000/health` - Server status

## 📊 Enterprise Features

### Compliance & Audit Logging

MockLoop MCP provides enterprise-grade compliance features:

- **Complete Audit Trails**: Every request/response logged with metadata
- **Regulatory Compliance**: GDPR, SOX, HIPAA compliance support
- **Performance Metrics**: P95/P99 response times, error rates
- **Security Monitoring**: Threat detection and analysis
- **Session Tracking**: Cross-request correlation and analysis

### Advanced Analytics

- **AI-Powered Insights**: Intelligent analysis and recommendations
- **Traffic Pattern Detection**: Automated anomaly detection
- **Performance Optimization**: AI-driven performance recommendations
- **Error Analysis**: Intelligent error categorization and resolution
- **Trend Analysis**: Historical performance and usage trends

## 🔄 Stateful Testing Workflows

MockLoop MCP supports complex, stateful testing workflows through advanced context management:

### Context Types

- **Test Session Context**: Maintain state across test executions
- **Workflow Context**: Complex multi-step testing orchestration
- **Agent Context**: AI agent state management and coordination
- **Global Context**: Cross-session data sharing and persistence

### Example: Stateful E-commerce Testing

```python
# Create test session context
session = mockloop.create_test_session_context(
    session_name="ecommerce_integration_test",
    configuration={
        "test_type": "integration",
        "environment": "staging",
        "ai_enhanced": True
    }
)

# Create workflow context for multi-step testing
workflow = mockloop.create_workflow_context(
    workflow_name="user_journey_test",
    parent_context=session["context_id"],
    steps=[
        "user_registration",
        "product_browsing",
        "cart_management",
        "checkout_process",
        "order_fulfillment"
    ]
)

# Execute stateful test workflow
for step in workflow["steps"]:
    # Update context with step data
    mockloop.update_context_data(
        context_id=workflow["context_id"],
        data={"current_step": step, "timestamp": datetime.now()}
    )
    
    # Execute step-specific tests
    test_result = mockloop.execute_test_plan(
        server_url="http://localhost:8000",
        test_plan=f"{step}_test_plan",
        context_id=workflow["context_id"]
    )
    
    # Create snapshot for rollback capability
    snapshot = mockloop.create_context_snapshot(
        context_id=workflow["context_id"],
        snapshot_name=f"{step}_completion"
    )

# Analyze complete workflow results
final_analysis = mockloop.analyze_test_results(
    test_results=workflow["results"],
    context_id=workflow["context_id"],
    include_recommendations=True
)
```

## 🚀 Running Generated Mock Servers

### Using Docker Compose (Recommended)

```bash
# Navigate to generated mock directory
cd generated_mocks/your_api_mock

# Start with dual-port architecture
docker-compose up --build

# Access points:
# Mocked API: http://localhost:8000
# Admin UI: http://localhost:8001
```

### Using Uvicorn Directly

```bash
# Install dependencies
pip install -r requirements_mock.txt

# Start the mock server
uvicorn main:app --reload --port 8000
```

### Enhanced Features Access

- **Admin UI**: `http://localhost:8001` - Enhanced management interface
- **API Documentation**: `http://localhost:8000/docs` - Interactive Swagger UI
- **Health Check**: `http://localhost:8000/health` - Server status and metrics
- **Log Analytics**: `http://localhost:8001/api/logs/search` - Advanced log querying
- **Performance Metrics**: `http://localhost:8001/api/logs/analyze` - AI-powered insights
- **Scenario Management**: `http://localhost:8001/api/mock-data/scenarios` - Dynamic testing

## 📈 Performance & Scalability

MockLoop MCP is designed for enterprise-scale performance:

### Performance Metrics

- **Response Times**: P50, P95, P99 percentile tracking
- **Throughput**: Requests per second monitoring
- **Error Rates**: Comprehensive error analysis
- **Resource Usage**: Memory, CPU, and network monitoring
- **Concurrency**: Multi-user load testing support

### Scalability Features

- **Horizontal Scaling**: Multi-instance deployment support
- **Load Balancing**: Built-in load balancing capabilities
- **Caching**: Intelligent response caching
- **Database Optimization**: Efficient SQLite and PostgreSQL support
- **Container Orchestration**: Kubernetes and Docker Swarm ready

## 🔒 Security Features

### Built-in Security

- **Authentication Middleware**: Configurable auth mechanisms
- **Rate Limiting**: Prevent abuse and DoS attacks
- **Input Validation**: Comprehensive request validation
- **Security Headers**: CORS, CSP, and security headers
- **Audit Logging**: Complete security event logging

### Security Testing

- **Vulnerability Assessment**: AI-powered security testing
- **Penetration Testing**: Automated security scenario generation
- **Compliance Checking**: Security standard compliance verification
- **Threat Modeling**: AI-driven threat analysis
- **Security Reporting**: Comprehensive security analytics

## 🔐 SchemaPin Integration - Cryptographic Schema Verification

MockLoop MCP now includes **SchemaPin integration** - the industry's first cryptographic schema verification system for MCP tools, preventing "MCP Rug Pull" attacks through ECDSA signature verification and Trust-On-First-Use (TOFU) key pinning.

### Revolutionary Security Enhancement

SchemaPin integration transforms MockLoop MCP into the most secure MCP testing platform by providing:

- **🔐 Cryptographic Verification**: ECDSA P-256 signatures ensure schema integrity
- **🔑 TOFU Key Pinning**: Automatic key discovery and pinning for trusted domains
- **📋 Policy Enforcement**: Configurable security policies (enforce/warn/log modes)
- **📊 Comprehensive Auditing**: Complete verification logs for compliance
- **🔄 Graceful Fallback**: Works with or without SchemaPin library
- **🏗️ Hybrid Architecture**: Seamless integration with existing MockLoop systems

### Quick Start Configuration

```python
from mockloop_mcp.schemapin import SchemaPinConfig, SchemaVerificationInterceptor

# Basic configuration
config = SchemaPinConfig(
    enabled=True,
    policy_mode="warn",  # enforce, warn, or log
    auto_pin_keys=False,
    trusted_domains=["api.example.com"],
    interactive_mode=False
)

# Initialize verification
interceptor = SchemaVerificationInterceptor(config)

# Verify tool schema
result = await interceptor.verify_tool_schema(
    tool_name="database_query",
    schema=tool_schema,
    signature="base64_encoded_signature",
    domain="api.example.com"
)

if result.valid:
    print("✓ Schema verification successful")
else:
    print(f"✗ Verification failed: {result.error}")
```

### Production Configuration

```python
# Production-ready configuration
config = SchemaPinConfig(
    enabled=True,
    policy_mode="enforce",  # Block execution on verification failure
    auto_pin_keys=True,     # Auto-pin keys for trusted domains
    key_pin_storage_path="/secure/path/keys.db",
    discovery_timeout=60,
    cache_ttl=7200,
    trusted_domains=[
        "api.corp.com",
        "tools.internal.com"
    ],
    well_known_endpoints={
        "api.corp.com": "https://api.corp.com/.well-known/schemapin.json"
    },
    revocation_check=True,
    interactive_mode=False
)
```

### Security Benefits

#### MCP Rug Pull Protection
SchemaPin prevents malicious actors from modifying tool schemas without detection:

- **Cryptographic Signatures**: Every tool schema is cryptographically signed
- **Key Pinning**: TOFU model prevents man-in-the-middle attacks
- **Audit Trails**: Complete verification logs for security analysis
- **Policy Enforcement**: Configurable responses to verification failures

#### Compliance & Governance
- **Regulatory Compliance**: Audit logs support GDPR, SOX, HIPAA requirements
- **Enterprise Security**: Integration with existing security frameworks
- **Risk Management**: Configurable security policies for different environments
- **Threat Detection**: Automated detection of schema tampering attempts

### Integration Examples

#### Basic Tool Verification
```python
# Verify a single tool
from mockloop_mcp.schemapin import SchemaVerificationInterceptor

interceptor = SchemaVerificationInterceptor(config)
result = await interceptor.verify_tool_schema(
    "api_call", tool_schema, signature, "api.example.com"
)
```

#### Batch Verification
```python
# Verify multiple tools efficiently
from mockloop_mcp.schemapin import SchemaPinWorkflowManager

workflow = SchemaPinWorkflowManager(config)
results = await workflow.verify_tool_batch([
    {"name": "tool1", "schema": schema1, "signature": sig1, "domain": "api.com"},
    {"name": "tool2", "schema": schema2, "signature": sig2, "domain": "api.com"}
])
```

#### MCP Proxy Integration
```python
# Integrate with MCP proxy for seamless security
class SecureMCPProxy:
    def __init__(self, config):
        self.interceptor = SchemaVerificationInterceptor(config)
    
    async def proxy_tool_request(self, tool_name, schema, signature, domain, data):
        # Verify schema before execution
        result = await self.interceptor.verify_tool_schema(
            tool_name, schema, signature, domain
        )
        
        if not result.valid:
            return {"error": "Schema verification failed"}
        
        # Execute tool with verified schema
        return await self.execute_tool(tool_name, data)
```

### Policy Modes

#### Enforce Mode
```python
config = SchemaPinConfig(policy_mode="enforce")
# Blocks execution on verification failure
# Recommended for production critical tools
```

#### Warn Mode
```python
config = SchemaPinConfig(policy_mode="warn")
# Logs warnings but allows execution
# Recommended for gradual rollout
```

#### Log Mode
```python
config = SchemaPinConfig(policy_mode="log")
# Logs events without blocking
# Recommended for monitoring and testing
```

### Key Management

#### Trust-On-First-Use (TOFU)
```python
# Automatic key discovery and pinning
key_manager = KeyPinningManager("keys.db")

# Pin key for trusted tool
success = key_manager.pin_key(
    tool_id="api.example.com/database_query",
    domain="api.example.com",
    public_key_pem=discovered_key,
    metadata={"developer": "Example Corp"}
)

# Check if key is pinned
if key_manager.is_key_pinned("api.example.com/database_query"):
    print("Key is pinned and trusted")
```

#### Key Discovery
SchemaPin automatically discovers public keys via `.well-known` endpoints:
```
https://api.example.com/.well-known/schemapin.json
```

Expected format:
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "algorithm": "ES256",
  "created_at": "2023-01-01T00:00:00Z"
}
```

### Audit & Compliance

#### Comprehensive Logging
```python
from mockloop_mcp.schemapin import SchemaPinAuditLogger

audit_logger = SchemaPinAuditLogger("audit.db")

# Verification events are automatically logged
stats = audit_logger.get_verification_stats()
print(f"Total verifications: {stats['total_verifications']}")
print(f"Success rate: {stats['successful_verifications'] / stats['total_verifications'] * 100:.1f}%")
```

#### Compliance Reporting
```python
# Generate compliance reports
from mockloop_mcp.mcp_compliance import MCPComplianceReporter

reporter = MCPComplianceReporter("audit.db")
report = reporter.generate_schemapin_compliance_report()

print(f"Compliance score: {report['compliance_score']:.1f}%")
print(f"Verification coverage: {report['verification_statistics']['unique_tools']} tools")
```

### Documentation & Examples

- **📚 Complete Integration Guide**: [`docs/guides/schemapin-integration.md`](docs/guides/schemapin-integration.md)
- **🔧 Basic Usage Example**: [`examples/schemapin/basic_usage.py`](examples/schemapin/basic_usage.py)
- **⚡ Advanced Patterns**: [`examples/schemapin/advanced_usage.py`](examples/schemapin/advanced_usage.py)
- **🏗️ Architecture Documentation**: [`SchemaPin_MockLoop_Integration_Architecture.md`](SchemaPin_MockLoop_Integration_Architecture.md)
- **🧪 Test Coverage**: 56 comprehensive tests (42 unit + 14 integration)

### Migration for Existing Users

SchemaPin integration is **completely backward compatible**:

1. **Opt-in Configuration**: SchemaPin is disabled by default
2. **No Breaking Changes**: Existing tools continue to work unchanged
3. **Gradual Rollout**: Start with `log` mode, progress to `warn`, then `enforce`
4. **Zero Downtime**: Enable verification without service interruption

```python
# Migration example: gradual rollout
# Phase 1: Monitoring (log mode)
config = SchemaPinConfig(enabled=True, policy_mode="log")

# Phase 2: Warnings (warn mode)
config = SchemaPinConfig(enabled=True, policy_mode="warn")

# Phase 3: Enforcement (enforce mode)
config = SchemaPinConfig(enabled=True, policy_mode="enforce")
```

### Performance Impact

SchemaPin is designed for minimal performance impact:

- **Verification Time**: ~5-15ms per tool (cached results)
- **Memory Usage**: <10MB additional memory
- **Network Overhead**: Key discovery only on first use
- **Database Size**: ~1KB per pinned key

### Use Cases

#### Development Teams
- **Secure Development**: Verify tool schemas during development
- **Code Review**: Ensure schema integrity in pull requests
- **Testing**: Validate tool behavior with verified schemas

#### Enterprise Security
- **Threat Prevention**: Block malicious schema modifications
- **Compliance**: Meet regulatory requirements with audit trails
- **Risk Management**: Configurable security policies
- **Incident Response**: Detailed logs for security analysis

#### DevOps & CI/CD
- **Pipeline Security**: Verify schemas in deployment pipelines
- **Environment Promotion**: Ensure schema consistency across environments
- **Monitoring**: Continuous verification monitoring
- **Automation**: Automated security policy enforcement

## �️ Future Development

### Upcoming Features 🚧

#### Enhanced AI Capabilities
- **Advanced ML Models**: Custom model training for API testing
- **Predictive Analytics**: AI-powered failure prediction
- **Intelligent Test Generation**: Self-improving test scenarios
- **Natural Language Testing**: Plain English test descriptions

#### Extended Protocol Support
- **GraphQL Support**: Native GraphQL API testing
- **gRPC Integration**: Protocol buffer testing support
- **WebSocket Testing**: Real-time communication testing
- **Event-Driven Testing**: Async and event-based API testing

#### Enterprise Integration
- **CI/CD Integration**: Native pipeline integration
- **Monitoring Platforms**: Datadog, New Relic, Prometheus integration
- **Identity Providers**: SSO and enterprise auth integration
- **Compliance Frameworks**: Extended regulatory compliance support

## 🤝 Contributing

We welcome contributions to MockLoop MCP! Please see our [Contributing Guidelines](docs/contributing/guidelines.md) for details.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/your-username/mockloop-mcp.git
cd mockloop-mcp

# Create development environment
python3 -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run quality checks
ruff check src/
bandit -r src/
```

### Community

- **GitHub Repository**: [mockloop/mockloop-mcp](https://github.com/mockloop/mockloop-mcp)
- **Issues & Bug Reports**: [GitHub Issues](https://github.com/mockloop/mockloop-mcp/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/mockloop/mockloop-mcp/issues)
- **Documentation**: [docs.mockloop.com](https://docs.mockloop.com)

## 📄 License

MockLoop MCP is licensed under the [MIT License](LICENSE).

---

## 🎉 Get Started Today!

Ready to revolutionize your API testing with the world's first AI-native testing platform?

```bash
pip install mockloop-mcp
```

**Join the AI-native testing revolution** and experience the future of API testing with MockLoop MCP!

**🚀 [Get Started Now](https://docs.mockloop.com/getting-started/installation/) →**
