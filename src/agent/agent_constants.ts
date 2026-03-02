// SSH Agent Protocol Message Types
export const SSH_AGENTC_REQUEST_IDENTITIES = 11;
export const SSH_AGENT_IDENTITIES_ANSWER = 12;
export const SSH_AGENTC_SIGN_REQUEST = 13;
export const SSH_AGENT_SIGN_RESPONSE = 14;
export const SSH_AGENTC_ADD_IDENTITY = 17;
export const SSH_AGENTC_REMOVE_IDENTITY = 18;
export const SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19;
export const SSH_AGENTC_ADD_ID_CONSTRAINED = 25;
export const SSH_AGENTC_EXTENSION = 27;
export const SSH_AGENT_FAILURE = 5;
export const SSH_AGENT_SUCCESS = 6;
export const SSH_AGENT_EXTENSION_FAILURE = 28;

// Sign Flags
export const SSH_AGENT_RSA_SHA2_256 = 2;
export const SSH_AGENT_RSA_SHA2_512 = 4;
