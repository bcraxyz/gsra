import json, base64, logging
from google.cloud import pubsub_v1
from google.cloud import compute_v1
import functions_framework

logger = logging.getLogger(__name__)

def is_firewall_open(project_id: str, firewall_name: str) -> bool:
    try:
        firewall_client = compute_v1.FirewallsClient()
        firewall = firewall_client.get(project=project_id, firewall=firewall_name)
        
        # Check if 0.0.0.0/0 is in source_ranges
        return "0.0.0.0/0" in firewall.source_ranges
    except Exception as e:
        logger.error(f"Error checking firewall rule: {str(e)}")
        return False

def disable_firewall_rule(project_id: str, firewall_id: str):
    try:
        firewall_client = compute_v1.FirewallsClient()
        firewall = firewall_client.get(project=project_id, firewall=firewall_id)
        firewall.disabled = True
        
        operation = firewall_client.patch(
            project=project_id,
            firewall=firewall_id,
            firewall_resource=firewall
        )
        operation.result()  # Wait for the operation to complete
        logger.info(f"Disabled firewall '{firewall.name}' in project '{project_id}'")
    except Exception as e:
        raise Exception(f"Failed to disable firewall: {str(e)}")

@functions_framework.cloud_event
def router(cloud_event):
    # Extract the Pub/Sub message
    pubsub_message = base64.b64decode(cloud_event.data["message"]["data"]).decode()
    message_data = json.loads(pubsub_message)

    if message_data.get("protoPayload", {}).get("methodName") == "v1.compute.firewalls.insert":
        project_id = message_data.get("resource", {}).get("labels", {}).get("project_id")
        firewall_name = message_data.get("resource", {}).get("labels", {}).get("firewall_name")
        
        if project_id and firewall_name:
            try:
                if is_firewall_open(project_id, firewall_name):
                    logger.warning(f"Open firewall rule detected: '{firewall_name}' in project '{project_id}'")
                    disable_firewall_rule(project_id, firewall_name)
                    logger.info(f"Successfully disabled open firewall rule '{firewall_name}' in project '{project_id}'")
                else:
                    logger.info(f"Firewall rule '{firewall_name}' in project '{project_id}' is not open. No action taken.")
            except Exception as e:
                logger.error(f"Error processing firewall rule: {str(e)}")
                return 'Error processing message', 500
        else:
            logger.error("Error: Project ID or Firewall rule name not provided in the message")
            return 'Invalid message data', 400
    else:
        logger.warning(f"Unhandled event type: {message_data.get('event_type')}")

    return 'Message processed successfully', 200

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
