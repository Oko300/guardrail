import subprocess
import json

service = [
    {
        "operation": "update",
        "id": "34137", # Changed to string
        "serviceName": "GuardRail Security Monitor",
        "serviceDescription": "Monitors AI agent transaction patterns to detect O2P attacks, behavioral drift, backrun risk and skill infection.",
        "serviceType": "A2MCP",
        "fee": "0",
        "endpoint": "https://guardrail-5q4v.onrender.com/api/v1/transaction/check"
    }
]

service_json = json.dumps(service)

result = subprocess.run(
    ["onchainos", "agent", "update", 
     "--agent-id", "5803",
     "--service", service_json],
    capture_output=True,
    text=True
)
print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
print("Return code:", result.returncode)