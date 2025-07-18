// token.ts
import { onRequest } from 'firebase-functions/v2/https';
import {
  DefaultClientCredentialFetcherProvider,
  TokenEndpoint,
} from 'oauth2-nodejs';
import { CustomGrantHandlerProvider } from './../granttype';
import { CloudFirestoreDataHandlerFactory } from '../data';
import { RequestWrapper } from '../models/request_wrapper';
import {
  sendFailureIndicator,
  sendSuccessIndicator,
  cloudLoggingMetadata,
  getProjectId
} from '../utils/sliLogger';
import cors from 'cors';
import express from 'express';

export function token(): ReturnType<typeof onRequest> {
  const tokenApp = express();

  tokenApp.use(cors({ origin: true }));
  tokenApp.use(express.json());
  tokenApp.use(express.urlencoded({ extended: true }));

  tokenApp.post('/', async (req, res) => {
    const metadataResourceType = "Firebase Auth";
    const metadataAction = "Token Registration";
    const metadataCriticalUserJourney = "SSO";
    const metadata = cloudLoggingMetadata(
      getProjectId(),
      metadataResourceType,
      metadataAction,
      metadataCriticalUserJourney,
    );

    try {
      if (!req || !req.headers) {
        return res.status(400).json({ error: "Malformed request" });
      }

      const request = new RequestWrapper(req);
      const tokenEndpoint = new TokenEndpoint();
      const clientCredentialFetcherProvider = new DefaultClientCredentialFetcherProvider();

      tokenEndpoint.grantHandlerProvider = new CustomGrantHandlerProvider(clientCredentialFetcherProvider);
      tokenEndpoint.clientCredentialFetcherProvider = clientCredentialFetcherProvider;
      tokenEndpoint.dataHandlerFactory = new CloudFirestoreDataHandlerFactory();

      const tokenEndpointResponse = await tokenEndpoint.handleRequest(request);

      sendSuccessIndicator(metadata, "Successfully provided token", metadataResourceType, metadataAction);

      return res
        .status(tokenEndpointResponse.code)
        .contentType("application/json; charset=UTF-8")
        .send(tokenEndpointResponse.body);

    } catch (error) {
      console.error("Token endpoint error:", error);

      sendFailureIndicator(metadata, "Failed to provide token", metadataResourceType, metadataAction);

      return res.status(500).json({
        error: "Token generation failed",
        details: error instanceof Error ? error.message : String(error),
      });
    }
  });

  tokenApp.all('*', (req, res) => {
    sendFailureIndicator(
      cloudLoggingMetadata(getProjectId(), "Firebase Auth", "Token Registration", "SSO"),
      "Failed to provide token, method not allowed",
      "Firebase Auth",
      "Token Registration"
    );
    return res.status(405).send("Method Not Allowed");
  });

  return onRequest(tokenApp);
}
