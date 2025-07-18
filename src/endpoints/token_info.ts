import { onRequest } from 'firebase-functions/v2/https';
import { RequestWrapper } from '../models';
import { TokeninfoEndpoint } from 'oauth2-nodejs';
import { CloudFirestoreDataHandlerFactory } from '../data';
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId
} from '../utils/sliLogger';

export function tokeninfo() {
  return onRequest(async (req, resp) => {
    const metadataResourceType = "Firebase Auth";
    const metadataAction = "Token Registration";
    const metadataCriticalUserJourney = "SSO";
    const metadata = cloudLoggingMetadata(
      getProjectId(),
      metadataResourceType,
      metadataAction,
      metadataCriticalUserJourney,
    );

    if (req.method === "GET") {
      const request = new RequestWrapper(req);
      const tokeninfoEndpoint = new TokeninfoEndpoint();
      tokeninfoEndpoint.dataHandlerFactory = new CloudFirestoreDataHandlerFactory();

      try {
        const tokeninfoEndpointResponse = await tokeninfoEndpoint.handleRequest(request);
        resp
          .contentType("application/json; charset=UTF-8")
          .status(tokeninfoEndpointResponse.code)
          .send(tokeninfoEndpointResponse.body);

        sendSuccessIndicator(
          metadata,
          "Successfully provided token",
          metadataResourceType,
          metadataAction,
        );
      } catch (error) {
        resp.status(500).send(error instanceof Error ? error.message : String(error));

        sendFailureIndicator(
          metadata,
          "Failed to provide token info",
          metadataResourceType,
          metadataAction,
        );
      }
    } else {
      resp.status(405).send("Method Not Allowed");

      sendFailureIndicator(
        metadata,
        "Failed to provide token info, method not allowed",
        metadataResourceType,
        metadataAction,
      );
    }
  });
}
