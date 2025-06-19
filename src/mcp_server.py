import os
import uuid
import copy
from enkryptai_sdk import *
from typing import List, Optional, Dict, Literal, Any
from pydantic import BaseModel
from mcp.server.fastmcp import FastMCP
import json

ENKRYPT_API_KEY = os.getenv("ENKRYPTAI_API_KEY")

ENKRYPT_BASE_URL = os.getenv("ENKRYPTAI_BASE_URL") or "https://api.enkryptai.com"

guardrails_client = GuardrailsClient(api_key=ENKRYPT_API_KEY, base_url=ENKRYPT_BASE_URL)

model_client = ModelClient(api_key=ENKRYPT_API_KEY, base_url=ENKRYPT_BASE_URL)

deployment_client = DeploymentClient(api_key=ENKRYPT_API_KEY, base_url=ENKRYPT_BASE_URL)

dataset_client = DatasetClient(api_key=ENKRYPT_API_KEY, base_url=ENKRYPT_BASE_URL)

redteam_client = RedTeamClient(api_key=ENKRYPT_API_KEY, base_url=ENKRYPT_BASE_URL)

mcp = FastMCP("EnkryptAI-MCP")

class SafetySystemPrompt(BaseModel):
    system_prompt: str

@mcp.tool()
def guardrails_detect(text: str, detectors_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect sensitive content using Guardrails.

    Args:
        ctx: The context object containing the request context.
        text: The text to detect sensitive content in.
        detectors_config: Dictionary of detector configurations. 
                          Each key should be the name of a detector, and the value should be a dictionary of settings for that detector.
                          Available detectors and their configurations are as follows:
                          
                          - injection_attack: Configured using InjectionAttackDetector model. Example: {"enabled": True}
                          - pii: Configured using PiiDetector model. Example: {"enabled": False, "entities": ["email", "phone"]}
                          - nsfw: Configured using NsfwDetector model. Example: {"enabled": True}
                          - toxicity: Configured using ToxicityDetector model. Example: {"enabled": True}
                          - topic: Configured using TopicDetector model. Example: {"enabled": True, "topic": ["politics", "religion"]}
                          - keyword: Configured using KeywordDetector model. Example: {"enabled": True, "banned_keywords": ["banned_word1", "banned_word2"]}
                          - policy_violation: Configured using PolicyViolationDetector model. Example: {"enabled": True, "need_explanation": True, "policy_text": "Your policy text here"}
                          - bias: Configured using BiasDetector model. Example: {"enabled": True}
                          - copyright_ip: Configured using CopyrightIpDetector model. Example: {"enabled": True}
                          - system_prompt: Configured using SystemPromptDetector model. Example: {"enabled": True, "index": "system_prompt_index"}
                          
                          Example usage: 
                          {
                              "injection_attack": {"enabled": True}, 
                              "nsfw": {"enabled": True}
                          }

    Returns:
        A dictionary containing the detection results with safety assessments.
    """
    
    response = guardrails_client.detect(text=text, config=detectors_config)
    
    return response.to_dict()

@mcp.tool()
def get_guardrails_policy() -> Dict[str, Any]:
    """
    Get all guardrails policies.
    """
    response = guardrails_client.get_policy_list()
    return response.to_dict()
    
@mcp.tool()
def retrieve_policy_configuration(policy_name: str) -> Dict[str, Any]:
    """
    Retrieve and print the policy configuration for a given policy name.

    Args:
        policy_name: The name of the policy to retrieve.

    Returns:
        A dictionary containing the policy configuration.
    """
    policy = guardrails_client.get_policy(policy_name=policy_name)

    # Return policy details as a dictionary
    return {
        "policy": policy.to_dict(),
        "name": policy.name,
        "detectors": policy.detectors.to_dict()
    }

@mcp.tool()
def add_guardrails_policy(policy_name: str, policy_description: str, detectors: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a new guardrails policy.

    Args:
        policy_name: The name of the policy to add.
        detectors: detectors_config: Dictionary of detector configurations. 
                          Each key should be the name of a detector, and the value should be a dictionary of settings for that detector.
                          Available detectors and their configurations are as follows:
                          
                          - injection_attack: Configured using InjectionAttackDetector model. Example: {"enabled": True}
                          - pii: Configured using PiiDetector model. Example: {"enabled": False, "entities": ["email", "phone"]}
                          - nsfw: Configured using NsfwDetector model. Example: {"enabled": True}
                          - toxicity: Configured using ToxicityDetector model. Example: {"enabled": True}
                          - topic: Configured using TopicDetector model. Example: {"enabled": True, "topic": ["politics", "religion"]}
                          - keyword: Configured using KeywordDetector model. Example: {"enabled": True, "banned_keywords": ["banned_word1", "banned_word2"]}
                          - policy_violation: Configured using PolicyViolationDetector model. Example: {"enabled": True, "need_explanation": True, "policy_text": "Your policy text here"}
                          - bias: Configured using BiasDetector model. Example: {"enabled": True}
                          - copyright_ip: Configured using CopyrightIpDetector model. Example: {"enabled": True}
                          - system_prompt: Configured using SystemPromptDetector model. Example: {"enabled": True, "index": "system_prompt_index"}
                          
                          Example usage: 
                          {
                              "injection_attack": {"enabled": True}, 
                              "nsfw": {"enabled": True}
                          }

    Returns:
        A dictionary containing the response message and policy details.
    """
    # Create a policy with a dictionary
    add_policy_response = guardrails_client.add_policy(
        policy_name=policy_name,
        config=detectors,
        description=policy_description
    )

    # Return policy details as a dictionary
    return add_policy_response.to_dict()

@mcp.tool()
def update_guardrails_policy(policy_name: str, detectors: Dict[str, Any], policy_description: str = "Updated policy configuration") -> Dict[str, Any]:
    """
    Update an existing guardrails policy with new configuration.

    Args:
        policy_name: The name of the policy to update.
        detectors: Dictionary of detector configurations. 
                          Each key should be the name of a detector, and the value should be a dictionary of settings for that detector.
                          Available detectors and their configurations are as follows:
                          
                          - injection_attack: Configured using InjectionAttackDetector model. Example: {"enabled": True}
                          - pii: Configured using PiiDetector model. Example: {"enabled": False, "entities": ["email", "phone"]}
                          - nsfw: Configured using NsfwDetector model. Example: {"enabled": True}
                          - toxicity: Configured using ToxicityDetector model. Example: {"enabled": True}
                          - topic: Configured using TopicDetector model. Example: {"enabled": True, "topic": ["politics", "religion"]}
                          - keyword: Configured using KeywordDetector model. Example: {"enabled": True, "banned_keywords": ["banned_word1", "banned_word2"]}
                          - policy_violation: Configured using PolicyViolationDetector model. Example: {"enabled": True, "need_explanation": True, "policy_text": "Your policy text here"}
                          - bias: Configured using BiasDetector model. Example: {"enabled": True}
                          - copyright_ip: Configured using CopyrightIpDetector model. Example: {"enabled": True}
                          - system_prompt: Configured using SystemPromptDetector model. Example: {"enabled": True, "index": "system_prompt_index"}
                          
                          Example usage: 
                          {
                              "injection_attack": {"enabled": True}, 
                              "nsfw": {"enabled": True}
                          }

    Returns:
        A dictionary containing the response message and updated policy details.
    """
    # Create a deep copy of the detectors dictionary to modify
    new_detectors_dict = detectors

    # Use the modified detectors dictionary to update the policy
    modify_policy_response = guardrails_client.modify_policy(
        policy_name=policy_name,
        config=new_detectors_dict,
        description=policy_description
    )

    # Return the response as a dictionary
    return modify_policy_response.to_dict()

@mcp.tool()
def remove_guardrails_policy(policy_name: str) -> Dict[str, Any]:
    """
    Remove an existing guardrails policy.

    Args:
        policy_name: The name of the policy to remove.

    Returns:
        A dictionary containing the response message and details of the deleted policy.
    """
    # Remove the policy
    delete_policy_response = guardrails_client.delete_policy(policy_name=policy_name)

    # Return the response as a dictionary
    return delete_policy_response.to_dict()

@mcp.tool()
def use_policy_to_detect(policy_name: str, text: str) -> Dict[str, Any]:
    """
    Use a policy to detect violations in the provided text.

    Args:
        policy_name: The name of the policy to use for detection.
        text: The text to check for policy violations.

    Returns:
        A dictionary containing the response message and details of the detection.
    """
    # Use policy to detect
    policy_detect_response = guardrails_client.policy_detect(
        policy_name=policy_name,
        text=text
    )

    # Return the response as a dictionary
    return policy_detect_response.to_dict()


@mcp.tool()
def add_model(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a new model using the provided configuration.

    Args:
        config: A dictionary containing the model configuration details. The structure of the ModelConfig is as follows:
            Example usage:
            {
                "model_saved_name": "example_model_name",  # The name under which the model is saved.
                "model_version": "v1",  # The version of the model.
                "testing_for": "foundationModels", # The purpose for which the model is being tested. (Always foundationModels)
                "model_name":"example_model",  # The name of the model. (e.g., gpt-4o, claude-3-5-sonnet, etc.)
                "model_config": {
                    "model_provider": "example_provider",  # The provider of the model. (e.g., openai, anthropic, etc.)
                    "endpoint_url":"https://api.example.com/model",  # The endpoint URL for the model only required if provider type is custom, otherwise don't include this key. 
                    "apikey":"example_api_key",  # The API key to access the model.
                    "system_prompt": "Some system prompt", # The system prompt for the model, only required if the user specifies, otherwise blank.
                    "input_modalities": ["text"], # The type of data the model works with (Possible values: text, image, audio) keep it as text unless otherwise specified.
                    "output_modalities": ["text"], # The type of data the model works with keep it as text only. If user asks for others, that modality is on our roadmap, please contact hello@enkryptai.com if you need early access to this.
                },
            }
    Ask the user for all the details before passing the config to the tool.

    Returns:
        A dictionary containing the response message and details of the added model.
    """
    # Add the model using the provided configuration
    add_model_response = model_client.add_model(config=copy.deepcopy(config))
    
    # Return the response as a dictionary
    return add_model_response.to_dict()

@mcp.tool()
def add_agent(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a new agent using the provided configuration.

    Args:
        config: A dictionary containing the agent configuration details. The structure of the AgentConfig is as follows:
            Example usage:
            {
                "model_saved_name": "example_agent_name",  # The name under which the agent is saved.
                "model_version": "v1",  # The version of the agent.
                "testing_for": "agents", # The purpose for which the agent is being tested. (Always agents)
                "model_name":"",  # Blank always
                "model_config": {
                    "model_provider": "custom", #Always custom
                    "endpoint_url": "", #the endpoint url of the agent (Mandatory)
                    "input_modalities": ["text"], #Always text
                    "output_modalities": ["text"], #Always text
                    "custom_headers": [{ # A list of custom headers to be sent to the agent. (Mandatory)
                        "key": "Content-Type",
                        "value": "application/json"
                    }...],
                    "custom_response_format": "", # Ask user for the response format of the agent in jq format (Mandatory)
                    "custom_response_content_type": "json", # The content type of the agent's response (always json) (Mandatory)
                    "custom_payload":{json that the user provides}, # Ask user for the payload to be sent to the agent (always keep placeholder for prompt as '{prompt}') (Mandatory)
                    "tools": [{ # Ask user for a list of tools to be used by the agent. (MANDATORY)
                            "name": "name of the tool",
                            "description": "description of the tool"
                            }...]
                },
            }
    NOTE: DO NOT ASSUME ANY FIELDS AND ASK THE USER FOR ALL THE DETAILS BEFORE PASSING THE CONFIG TO THE TOOL.
    Ask the user for all the mandatory details before passing the config to the tool.

    Returns:
        A dictionary containing the response message and details of the added agent.
    """
    # Add the agent using the provided configuration
    add_agent_response = model_client.add_model(config=copy.deepcopy(config))
    
    # Return the response as a dictionary
    return add_agent_response.to_dict()

@mcp.tool()
def add_model_from_url(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a new model using the provided configuration.

    Args:
        config: A dictionary containing the url model configuration details. The structure of the ModelConfig is as follows:
            Example usage:
            {
                "model_saved_name": "example_model_name",  # The name under which the model is saved.
                "model_version": "v1",  # The version of the model.
                "testing_for": "URL", # The purpose for which the model is being tested. (Always URL)
                "model_name":"example_url",  # The url of the chatbot site provided by user.
                "model_config": {
                    "model_provider": "url",  # Always fixed to 'url'
                    "endpoint_url":"example_url",  # Same as model_name
                    "apikey":"none",  # The API key to access the model.
                    "input_modalities": ["text"], # Always fixed to ['text']
                    "output_modalities": ["text"], # Always fixed to ['text']
                },
            }
    Ask the user for the url before passing the config to the tool.

    Returns:
        A dictionary containing the response message and details of the added model.
    """
    # Add the model using the provided configuration
    add_model_response = model_client.add_model(config=copy.deepcopy(config))
    
    # Return the response as a dictionary
    return add_model_response.to_dict()

@mcp.tool()
def list_models() -> Dict[str, Any]:
    """
    List all models and print details of the first model.

    Returns:
        A dictionary containing the list of models.
    """
    # List all models
    models = model_client.get_model_list()

    # Return the list of models as a dictionary
    return models.to_dict()

@mcp.tool()
def get_model_details(model_saved_name: str, model_version: str) -> Dict[str, Any]:
    """
    Retrieve details of a specific model using its saved name.

    Args:
        model_saved_name: The name under which the model is saved.
        model_version: The version of the model to be used for the redteam task.
    Returns:
        A dictionary containing the details of the model.
    """
    # Retrieve model details
    model_details = model_client.get_model(model_saved_name=model_saved_name, model_version=model_version)

    # Return the model details as a dictionary
    return model_details.to_dict()

@mcp.tool()
def modify_model_config(new_model_config: Dict[str, Any], test_model_saved_name: str) -> Dict[str, Any]:
    """
    Modify the model configuration and update the model.

    Args:
        new_model_config: The sample model configuration to be modified.
            Example usage:
                {
                    "model_saved_name": "example_model_name",  # The name under which the model is saved.
                    "testing_for": "LLM",  # The purpose for which the model is being tested. (Always LLM)
                    "model_name": "example_model",  # The name of the model. (e.g., gpt-4o, claude-3-5-sonnet, etc.)
                    "modality": "text",  # The type of data the model works with (e.g., text, image).
                    "model_config": {
                        "model_version": "1.0",  # The version of the model.
                        "model_provider": "example_provider",  # The provider of the model. (e.g., openai, anthropic, etc.)
                        "endpoint_url": "https://api.example.com/model",  # The endpoint URL for the model. 
                        "apikey": "example_api_key",  # The API key to access the model.
                    },
                }
        test_model_saved_name: The saved name of the model to be tested.

    Returns:
        A dictionary containing the response message and details of the modified model.
    """
    # Modify model configuration

    # Update the model_saved_name if needed
    # new_model_config["model_saved_name"] = "New Model Name"

    old_model_saved_name = None
    if new_model_config["model_saved_name"] != test_model_saved_name:
        old_model_saved_name = test_model_saved_name

    modify_response = model_client.modify_model(old_model_saved_name=old_model_saved_name, config=new_model_config)

    # Print as a dictionary
    return modify_response.to_dict()

@mcp.tool()
def remove_model(test_model_saved_name: str) -> Dict[str, Any]:
    """
    Remove a model.

    Args:
        test_model_saved_name: The saved name of the model to be removed.

    Returns:
        A dictionary containing the response message and details of the deleted model.
    """
    # Remove the model
    delete_response = model_client.delete_model(model_saved_name=test_model_saved_name)

    # Print as a dictionary
    return delete_response.to_dict()

@mcp.tool()
def add_redteam_task(model_saved_name: str, model_version: str, redteam_model_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a redteam task using a saved model.

    Args:
        model_saved_name: The saved name of the model to be used for the redteam task.
        model_version: The version of the model to be used for the redteam task.
        redteam_model_config: The configuration for the redteam task.
            Example usage:
                sample_redteam_model_config = {
                "test_name": redteam_test_name,
                "dataset_name": "standard",
                "redteam_test_configurations": { #IMPORTANT: Before setting the redteam test config, ask the user which tests they would want to run and the sample percentage.
                    "bias_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "cbrn_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "insecure_code_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "toxicity_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "harmful_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                },
            }
            These are the only 5 tests available. Ask the user which ones to run and sample percentage for each as well.

            Before calling this tool, ensure that the model name is availble. If not, save a new model then start the redteaming task.

            NOTE: Tests compatible with audio and image modalities are only: cbrn and harmful. Other test types are not compatible with audio and image modalities.

    Returns:
        A dictionary containing the response message and details of the added redteam task.
    """
    # Use a dictionary to configure a redteam task
    add_redteam_model_response = redteam_client.add_task_with_saved_model(config=redteam_model_config, model_saved_name=model_saved_name, model_version=model_version)

    # Print as a dictionary
    return add_redteam_model_response.to_dict()

@mcp.tool()
def add_custom_redteam_task(model_saved_name: str, model_version: str, custom_redteam_model_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a custom use-case basedredteam task using a saved model.
    NOTE: Not compatible with audio and image modalities.

    Args:
        model_saved_name: The saved name of the model to be used for the redteam task.
        model_version: The version of the model to be used for the redteam task.
        custom_redteam_model_config: The configuration for the customredteam task.
            Example usage:
                sample_redteam_model_config = {
                "test_name": redteam_test_name,
                "dataset_configuration": { #Ask user for all these details, do not fill it on your own (system_description, policy_description and tools)
                    "system_description": "", # The system description of the model for the custom use-case. (Mandatory)
                    "policy_description": "", # The policy which the model for the custom use-case should follow. (Optional)
                    "tools": [
                        {
                            "name": "web_search", # The name of the tool to be used for the custom use-case. (Optional)
                            "description": "The tool web search is used to search the web for information related to finance." # The description of the tool to be used for the custom use-case. (Optional)
                        }
                    ],
                    #The following are the default values for the custom use-case. Change them only if the user asks for a different test size.
                    "max_prompts": 500, # The maximum number of prompts to be used for the custom use-case.
                    "scenarios": 2, # The number of scenarios to be used for the custom use-case.
                    "categories": 2, # The number of categories to be used for the custom use-case.
                    "depth": 1, # The depth of the custom use-case.
                    }
                "redteam_test_configurations": { #IMPORTANT: Before setting the redteam test config, ask the user which tests they would want to run and the sample percentage. Note: The custom test is mandatory. other 5 are optional.
                    "bias_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "cbrn_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "insecure_code_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "toxicity_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                    "harmful_test": {
                        "sample_percentage": 2,
                        "attack_methods": {"basic": ["basic"]},
                    },
                     "custom_test": {
                        "sample_percentage": 100, # The sample percentage for the custom use-case. Keep it at 100 unless the user asks for a different sample percentage.
                        "attack_methods": {"basic": ["basic"]},
                    }
                },
            }

            Befor calling this tool, ensure that the model name is availble. If not, save a new model then start the redteaming task.

    Returns:
        A dictionary containing the response message and details of the added redteam task.
    """
    # Use a dictionary to configure a redteam task
    add_redteam_model_response = redteam_client.add_custom_task_with_saved_model(config=custom_redteam_model_config, model_saved_name=model_saved_name, model_version=model_version)

    # Print as a dictionary
    return add_redteam_model_response.to_dict()

@mcp.tool()
def add_agent_redteam_task(agent_saved_name: str, agent_version: str, agent_redteam_model_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a redteam task using a saved agent.

    Args:
        agent_saved_name: The saved name of the agent to be used for the redteam task.
        agent_version: The version of the agent to be used for the redteam task.
        agent_redteam_model_config: The configuration for the redteam task. ASK USER FOR ALL THESE DETAILS.
            Example usage:
                sample_redteam_model_config = {
                "test_name": redteam_test_name,
                "dataset_configuration": { #Ask user for all these details, do not fill it on your own (system_description, policy_description. Tools can be gotten from agent config otherwise ask user)
                    "system_description": "Ask user for this", # Ask user for the system description of the agent for the custom use-case. (Mandatory exactly same as what the user has input)
                    "policy_description": "Ask user for this", # Ask user for the policy which the agent for the custom use-case should follow. (Optional)
                    "tools": [
                        {
                            "name": "ask user for this", # The name of the tool to be used for the custom use-case. (Mandatory)
                            "description": "ask user for this" # The description of the tool to be used for the custom use-case. (Mandatory)
                        }
                    ],
                    #The following are the default values for the custom use-case. Change them only if the user asks for a different test size.
                    "max_prompts": 500, # The maximum number of prompts to be used for the custom use-case.
                    "scenarios": 2, # The number of scenarios to be used for the custom use-case.
                    "categories": 2, # The number of categories to be used for the custom use-case.
                    "depth": 1, # The depth of the custom use-case.
                    }
                "redteam_test_configurations": { #IMPORTANT: Before setting the redteam test config, ask the user which tests they would want to run and the sample percentage
                    "alignment_and_governance_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    },
                    "input_and_content_integrity_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    },
                    "infrastructure_and_integration_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    },
                    "security_and_privacy_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    },
                    "human_factors_and_societal_impact_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    },
                    "access_control_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    },
                    "physical_and_actuation_safety_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    },
                    "reliability_and_monitoring_test": {
                        "sample_percentage": 2,
                        "attack_methods": {
                        "basic": [
                            "basic"
                        ],
                        "advanced": {
                            "static": [
                            "encoding"
                            ]
                        }
                        }
                    }
                },
            }

    Returns:
        A dictionary containing the response message and details of the added redteam task.
    """
    # Use a dictionary to configure a redteam task
    add_redteam_model_response = redteam_client.add_custom_task_with_saved_model(config=agent_redteam_model_config, model_saved_name=agent_saved_name, model_version=agent_version)

    # Print as a dictionary
    return add_redteam_model_response.to_dict()

@mcp.tool()
def get_redteam_task_status(test_name: str) -> Dict[str, Any]:
    """
    Get the status of a redteam task.

    Args:
        test_name: The name of the redteam test.

    Returns:
        A dictionary containing the status of the redteam task.
    """
    # Get redteam task status
    redteam_task_status = redteam_client.status(test_name=test_name)

    return redteam_task_status.to_dict()

@mcp.tool()
def get_redteam_task_details(test_name: str) -> Dict[str, Any]:
    """
    Retrieve details of a redteam task.

    Args:
        test_name: The name of the redteam test.

    Returns:
        A dictionary containing the details of the redteam task including the system prompt of the target model used.
    """
    # Retrieve redteam task details
    redteam_task = redteam_client.get_task(test_name=test_name)

    # Print as a dictionary
    return redteam_task.to_dict()

@mcp.tool()
def list_redteam_tasks(status: Optional[str] = None) -> Dict[str, Any]:
    """
    List all redteam tasks, optionally filtered by status.

    Args:
        status: The status to filter tasks by (e.g., "Finished"). If None, list all tasks.

    Returns:
        A dictionary containing the list of redteam tasks.
    """
    # List redteam tasks
    redteam_tasks = redteam_client.get_task_list(status=status)

    return redteam_tasks.to_dict()

@mcp.tool()
def get_redteam_task_results_summary(test_name: str) -> str:
    """
    Get the results summary of a redteam task.

    Args:
        test_name: The name of the redteam test.

    Returns:
        A dictionary containing the results summary of the redteam task.

        After getting the results summary, suggest the following actions to the user to mitigate the risk:
        1. Mitigate the risks by using a tailored system prompt
        2. Create a guardrails policy to mitigate the risks
    """
    # Get redteam task results summary
    redteam_results_summary = redteam_client.get_result_summary(test_name=test_name)

    redteam_results_summary = redteam_results_summary.to_dict()

    test_types = redteam_results_summary["summary"]["test_type"]
    import concurrent.futures

    redteam_results_summary2 = {}

    def fetch_test_type_summary(test_type):
        redteam_results_summary_test_type = redteam_client.get_result_summary_test_type(test_name=test_name, test_type=test_type)
        return test_type, redteam_results_summary_test_type.to_dict()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_test_type = {executor.submit(fetch_test_type_summary, test_type): test_type for test in test_types for test_type in test.keys()}
        for future in concurrent.futures.as_completed(future_to_test_type):
            test_type, summary = future.result()
            redteam_results_summary2[f"{test_type}_full_summary"] = summary

    redteam_results_summary2["mitigations_possible"] = "Safer System Prompt"
    # Return the results summary as a dictionary
    return redteam_results_summary2

@mcp.tool()
def harden_system_prompt(redteam_results_summary: Dict[str, Any], system_prompt: str) -> Dict[str, Any]:
    """
    Harden the system prompt by using the redteam results summary and the system prompt.

    Args:
        redteam_results_summary: A dictionary containing only the top 20 categories of the redteam results summary in terms of success percent (retrieve using get_redteam_task_results_summary tool).
                                NOTE: If there are more than 20 items in category array, only pass the top 20 categories with the highest success percent.
                                Format: {
                                    "category": [
                                        {
                                            "Bias": {
                                                "total": 6,
                                                "test_type": "adv_info_test",
                                                "success(%)": 66.67
                                            }
                                        }, contd.
                                    ]
                                }
        system_prompt: The system prompt to be hardened (retrieve using get_redteam_task_details tool).

    Returns:
        A dictionary containing the response message and details of the hardened system prompt.
    """
    # Harden the system prompt using the provided configuration
    config = {
        "system_prompt": system_prompt,
        "redteam_summary": redteam_results_summary
    }
    harden_system_prompt_response = redteam_client.risk_mitigation_system_prompt(config=config)

    # Return the response as a dictionary
    return harden_system_prompt_response.to_dict()

@mcp.tool()
def mitigation_guardrails_policy(redteam_results_summary: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a guardrails policy by using the redteam results summary.

    Args:
        redteam_results_summary: A dictionary containing only the top 20 categories of the redteam results summary in terms of success percent (retrieve using get_redteam_task_results_summary tool).
                                NOTE: If there are more than 20 items in category array, only pass the top 20 categories with the highest success percent.
                                Format: {
                                    "category": [
                                        {
                                            "Bias": {
                                                "total": 6,
                                                "test_type": "adv_info_test",
                                                "success(%)": 66.67
                                            }
                                        }, contd.
                                    ]
                                }

    Returns:
        A dictionary containing the response message and details of the created guardrails policy.

    After getting the configuration, create the guardrails policy using the add_guardrails_policy tool.
    """
    config = {
        "redteam_summary": redteam_results_summary
    }
    # Create the guardrails policy using the provided configuration
    mitigation_guardrails_policy_response = redteam_client.risk_mitigation_guardrails_policy(config=config)
    
    # Return the response as a dictionary
    return mitigation_guardrails_policy_response.to_dict()

@mcp.tool()
def add_deployment(deployment_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a new deployment using the provided configuration.

    Args:
        deployment_config: A dictionary containing the deployment configuration details.

        Example Usage:
        {
            "deployment_config": {
                sample_deployment_config = {
                "name": deployment_name,
                "model_saved_name": model_saved_name,
                "input_guardrails_policy": {
                    "policy_name": policy_name,
                    "enabled": True,
                    "additional_config": {
                        "pii_redaction": False  #Add these if any additional detectors than that in the policy are needed
                    },
                    "block": [
                        "injection_attack",    # Could be any of the active detectors (Ask user if they want to block)
                        "policy_violation"
                    ]
                },
                "output_guardrails_policy": {
                    "policy_name": policy_name,
                    "enabled": False,
                    "additional_config": {
                        "hallucination": False,  #Add these if any additional detectors than that in the policy are needed
                        "adherence": False,
                        "relevancy": False
                    },
                    "block": [
                        "nsfw"    # Could be any of the active detectors (Ask user if they want to block)
                    ]
                },
            }
        }

    Always ask user if they want to block any of the detectors in the policy for both input and output. (if you dont know what detectors are present in the policy, you can use the get_guardrails_policy tool)
    Returns:
        A dictionary containing the response message and details of the added deployment.
    """
    # Add the deployment using the provided configuration
    add_deployment_response = deployment_client.add_deployment(deployment_config)

    # Return the response as a dictionary
    return add_deployment_response.to_dict()

@mcp.tool()
def get_deployment_details(deployment_name: str) -> Dict[str, Any]:
    """
    Retrieve details of a specific deployment using its name.

    Args:
        deployment_name: The name of the deployment to retrieve details for.

    Returns:
        A dictionary containing the details of the deployment.
    """
    # Retrieve deployment details
    deployment_details = deployment_client.get_deployment(deployment_name=deployment_name)

    # Return the deployment details as a dictionary
    return deployment_details.to_dict()

@mcp.tool()
def list_deployments() -> Dict[str, Any]:
    """
    List all deployments and print details of the first deployment.

    Returns:
        A dictionary containing the list of deployments.
    """
    # List all deployments
    deployments = deployment_client.list_deployments()

    # Return the list of deployments as a dictionary
    return deployments.to_dict()

@mcp.tool()
def modify_deployment_config(deployment_name: str, new_deployment_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Modify the deployment configuration and update the deployment.

    Args:
        deployment_name: The name of the deployment to be modified.
        new_deployment_config: The new deployment configuration to be modified.

        Example Usage:
        {
            "deployment_config": {
                sample_deployment_config = {
                "name": deployment_name,
                "model_saved_name": model_saved_name,
                "input_guardrails_policy": {
                    "policy_name": policy_name,
                    "enabled": True,
                    "additional_config": {
                        "pii_redaction": False  #Add these if any additional detectors than that in the policy are needed
                    },
                    "block": [
                        "injection_attack",    # Could be any of the active detectors (Ask user if they want to block)
                        "policy_violation"
                    ]
                },
                "output_guardrails_policy": {
                    "policy_name": policy_name,
                    "enabled": False,
                    "additional_config": {
                        "hallucination": False,  #Add these if any additional detectors than that in the policy are needed
                        "adherence": False,
                        "relevancy": False
                    },
                    "block": [
                        "nsfw"    # Could be any of the active detectors (Ask user if they want to block)
                    ]
                },
            }
        }

    Returns:
        A dictionary containing the response message and details of the modified deployment.
    """
    # Modify the deployment using the provided configuration
    modify_deployment_response = deployment_client.modify_deployment(deployment_name=deployment_name, config=new_deployment_config)

    # Return the response as a dictionary
    return modify_deployment_response.to_dict()

@mcp.tool()
def remove_deployment(deployment_name: str) -> Dict[str, Any]:
    """
    Remove an existing deployment.

    Args:
        deployment_name: The name of the deployment to remove.

    Returns:
        A dictionary containing the response message and details of the deleted deployment.
    """
    # Remove the deployment
    delete_deployment_response = deployment_client.delete_deployment(deployment_name=deployment_name)

    # Return the response as a dictionary
    return delete_deployment_response.to_dict()



if __name__ == "__main__":
    # result = redteam_client.get_task(test_name="ResMed RedTeaming Test EU Policy")
    # print(result.to_dict())
    mcp.run()
