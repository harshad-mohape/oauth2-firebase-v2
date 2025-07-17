
import { onRequest } from 'firebase-functions/v2/https';
import {
  DefaultClientCredentialFetcherProvider,
  TokenEndpoint,
} from 'oauth2-nodejs';
import { CustomGrantHandlerProvider } from './../granttype';
import { CloudFirestoreDataHandlerFactory } from '../data';
import {
  RequestWrapper,
} from '../models/request_wrapper';
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId
} from '../utils/sliLogger'


export function token() {
  
  // SLI Logger
  const metadataResourceType = "Firebase Auth";
  const metadataAction = "Token Registration";
  const metadataCriticalUserJourney = "SSO";
  const metadata = cloudLoggingMetadata(
    getProjectId(),
    metadataResourceType,
    metadataAction,
    metadataCriticalUserJourney,
  );

  return onRequest(async (req, resp) => {
    console.log("token", req.method, req.url);
    if (req.method === "POST") {
      const request = new RequestWrapper(req);
      const tokenEndpoint = new TokenEndpoint();
      const clientCredentialFetcherProvider = new DefaultClientCredentialFetcherProvider();

      tokenEndpoint.grantHandlerProvider = new CustomGrantHandlerProvider(
        clientCredentialFetcherProvider
      );
      tokenEndpoint.clientCredentialFetcherProvider = clientCredentialFetcherProvider;
      tokenEndpoint.dataHandlerFactory = new CloudFirestoreDataHandlerFactory();

      try {
        const tokenEndpointResponse = await tokenEndpoint.handleRequest(request);
        console.log("token Response", tokenEndpointResponse);
        resp.contentType("application/json; charset=UTF-8");
        console.log("resp send", resp, resp.status(tokenEndpointResponse.code).send(tokenEndpointResponse.body));
        resp.status(tokenEndpointResponse.code).send(tokenEndpointResponse.body);

        // SLI Logger
        sendSuccessIndicator(
          metadata,
          "Successfully provided token",
          metadataResourceType,
          metadataAction,
        );
      } catch (error) {
        resp.status(500).send(error.toString());

        // SLI Logger
        sendFailureIndicator(
          metadata,
          "Failed to provide token",
          metadataResourceType,
          metadataAction,
        );
      }
    } else {
      resp.status(405).send("Method Not Allowed");

      // SLI Logger
      sendFailureIndicator(
        metadata,
        "Failed to provide token, method not allowed",
        metadataResourceType,
        metadataAction,
      );
    }
  });
}