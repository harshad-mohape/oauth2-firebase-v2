/**
 * How to use:
 * 1. Import the following functions from this module:
 *    a. sendSuccessIndicator
 *    b. sendFailureIndicator
 *    c. cloudLoggingMetadata
 *    d. getProjectId()
 * 2. Identify the location of the script where you'd like to log out data
 *    a. Initiate a metadata object with cloudLoggingMetadata
 *    b. Identify success and failure locations and call sendSuccessIndicator/sendFailureIndicator
 * Note: It is imperative that any time this module is used to instrument code, a "success" message must have a corresponding "failure" message
 * somewhere to represent when an exception occurs. Otherwise we would only ever log successful events and corrupt our SLI's
 * Note: Refer to the usage within functions\firestore\employer\employer.js
 */

const { Logging } = require("@google-cloud/logging");
const { onCall } = require("firebase-functions/v2/https");

const projectId = process.env.GCP_PROJECT || process.env.GCLOUD_PROJECT;
const logName = `reactAppLog.${projectId}`;
const logging = new Logging({ projectId });
const log = logging.log(logName);

const writeLog = async (entry) => {
  try {
    await log.write(entry);
    console.log("Finished writing log entry");
  } catch (error) {
    console.log("Error writing log entry, error: ", error.message);
  }
};

const sendCloudLogging = async (text, metadata) => {
  const entry = log.entry(metadata, text);
  console.log(`Preparing to log, text: ${text}`);
  await writeLog(entry);
};

const getEnvName = (projectId) => {
  return projectId.split("-")[0];
};

const sliLogger = onCall(async (request) => {
  const data = request.data;
  try {
    const metadata = {
      severity: data.sevLevel,
      resource: { type: "global" },
      labels: {
        env: getEnvName(projectId),
        context: JSON.stringify(data.messageContext),
        resourceType: data.resourceType,
        action: data.action,
        resultStatus: data.resultStatus,
        criticalUserJourney: data.cuj,
      },
    };
    await sendCloudLogging(data.message, metadata);
    return {
      status: "success",
      message: data.message,
      metadata: metadata,
    };
  } catch (e) {
    console.error("HTTPS callable function error: ", e);
    return {
      status: "failure",
      error: e.message,
    };
  }
});

const cloudLoggingMetadata = (
  projectID,
  resourceType,
  action,
  criticalUserJourney,
) => {
  return {
    severity: "",
    resource: { type: "global" },
    labels: {
      env: getEnvName(projectID),
      context: {},
      resourceType: resourceType,
      action: action,
      resultStatus: "",
      criticalUserJourney: criticalUserJourney,
    },
  };
};

const formatMessage = (projectId, resourceType, action, resultStatus) => {
  return `${projectId}-${resourceType}-${action}-${resultStatus}`;
};

const getProjectId = () => {
  return process.env.GCP_PROJECT || process.env.GCLOUD_PROJECT;
};

const sendFailureIndicator = (
  metadata,
  details,
  metadataResourceType,
  metadataAction,
) => {
  metadata.severity = "ERROR";
  metadata.labels.resultStatus = "failure";
  metadata.labels.context = {
    details,
  };

  sendCloudLogging(
    formatMessage(
      getProjectId(),
      metadataResourceType,
      metadataAction,
      metadata.labels.resultStatus,
    ),
    metadata,
  );
};

const sendSuccessIndicator = (
  metadata,
  details,
  metadataResourceType,
  metadataAction,
) => {
  metadata.severity = "INFO";
  metadata.labels.resultStatus = "success";
  metadata.labels.context = {
    details,
  };

  sendCloudLogging(
    formatMessage(
      getProjectId(),
      metadataResourceType,
      metadataAction,
      metadata.labels.resultStatus,
    ),
    metadata,
  );
};

module.exports = {
  getEnvName,
  cloudLoggingMetadata,
  formatMessage,
  getProjectId,
  sendFailureIndicator,
  sendSuccessIndicator,
  sliLogger,
};
