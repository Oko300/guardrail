import subprocess, json

service = [{"serviceName": "GuardRail Security Monitor", "serviceDescription": "Monitors AI agent transaction patterns to detect O2P attacks, behavioral drift, backrun risk and skill infection.", "serviceType": "A2MCP", "fee": "1", "endpoint": "https://guardrail-5q4v.onrender.com/api/v1/transaction/check"}]

result = subprocess.run(
    [
        "onchainos", "agent", "create",
        "--role", "asp",
        "--name", "GuardRail",
        "--description", "Monitors AI agent transaction patterns to detect O2P attacks, behavioral drift, backrun risk and skill infection.",
        "--picture", "https://static.okx.com/cdn/web3/wallet/marketplace/headimages/agent/avatar/19db5672-531d-46d5-84ed-e8f4a0151f9a.png",
        "--service", json.dumps(service)
    ],
    capture_output=True, text=True
)
print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
print("CODE:", result.returncode)